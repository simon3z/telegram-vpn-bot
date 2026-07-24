use std::time::{Duration, SystemTime};

use tracing::{debug, info};

use super::types::*;
use crate::state::*;

/// Health checks. Examines VPN connection state and per-peer timers.
///
/// Only processes **enabled** peers that are currently on the interface.
/// Disabled peers are handled exclusively by the reconcile phase.
///
/// Returns a list of notification events triggered by health issues (timeouts,
/// idle detection).
pub(crate) async fn run_health_checks(
    state: &mut SystemState,
    snapshot: &PollSnapshot,
    first_hs_timeout: &Duration,
    idle_timeout: &Duration,
) -> Vec<NotificationEvent> {
    let now = SystemTime::now();
    let mut events = Vec::new();

    // Only process peers that are DESIRED to be enabled AND actually present.
    for ps in &mut state.peers {
        if ps.desired != DesiredState::Enabled {
            // Disabled peers are handled by reconcile, not health checks.
            continue;
        }

        let cidr = &ps.config.allowed_ips;
        let pubkey = &ps.config.public_key;

        let peer_on_iface = snapshot.peer_on_iface(pubkey);

        if !peer_on_iface {
            // Peer absent from interface — reconcile will add it; nothing for
            // health checks to observe yet.
            debug!(
                "enabled peer not on interface, waiting for reconcile: peer={}, cidr={}",
                ps.config.name, cidr
            );
            continue;
        }

        // Peer is on the interface — track its handshake health regardless of
        // route state. Missing routes are reconcile's job, not a reason to skip
        // health monitoring.

        if let Some(peer) = snapshot.find_peer(pubkey) {
            if let Some(event) =
                process_one_peer(ps, peer, now, *first_hs_timeout, *idle_timeout).await
            {
                info!(
                    "issuing notification: user={} peer={} kind={}",
                    event.user_id,
                    event.peer_name,
                    event.kind.label()
                );
                events.push(event);
            }
        }
    }

    events
}

/// Record when we first observed this peer on the interface. Only sets once;
/// subsequent polls leave the timestamp untouched.
fn record_first_seen(ps: &mut PeerState, now: SystemTime) {
    if ps.first_seen_at.is_none() {
        ps.first_seen_at = Some(now);
    }
}

/// Capture the kernel-reported handshake timestamp, skipping zero-valued ones.
/// The library wraps "no handshake" into UNIX_EPOCH, which must be filtered out.
///
/// Returns whether the peer had no recorded handshake *before* this update.
fn capture_kernel_handshake(ps: &mut PeerState, peer: &defguard_wireguard_rs::peer::Peer) -> bool {
    let had_previously_no_handshake = ps.last_handshake.is_none();
    if let Some(hs_time) = peer.last_handshake {
        if hs_time > SystemTime::UNIX_EPOCH {
            ps.last_handshake = Some(hs_time);
        }
    }
    had_previously_no_handshake
}

/// Process one enabled peer confirmed present on the interface.
///
/// Flow:
///
/// 1. Record [`PeerState::first_seen_at`] on first encounter (subsequent
///    polls leave it untouched).
/// 2. Capture the kernel-reported `last_handshake`, filtering out bogus
///    `UNIX_EPOCH` values that lib-wg uses to represent "no handshake."
/// 3. If this poll detected a handshake transition (none → some), emit a
///    [`NotificationKind::ConnectionEstablished`] event and stop.
/// 4. Otherwise dispatch to the appropriate watchdog based on phase:
///    - **No handshake yet** → connection-deadline timer
///      ([`super::timeouts::check_first_handshake_timeout`]).
///    - **Handshake captured** → idle watchdog
///      ([`super::timeouts::check_idle_timeout`]).
///
/// Returns a notification event only when something changed or a deadline
/// fired; otherwise returns `None`.
pub(crate) async fn process_one_peer(
    ps: &mut PeerState,
    peer: &defguard_wireguard_rs::peer::Peer,
    now: SystemTime,
    first_hs_timeout: Duration,
    idle_timeout: Duration,
) -> Option<NotificationEvent> {
    record_first_seen(ps, now);
    let had_no_handshake = capture_kernel_handshake(ps, peer);

    // Transition: no handshake → handshake received. Notify the user once.
    if had_no_handshake && ps.last_handshake.is_some() {
        info!("connection established: peer={}", ps.config.name);
        return Some(NotificationEvent {
            user_id: ps.config.telegram_id,
            peer_name: ps.config.name.clone(),
            kind: NotificationKind::ConnectionEstablished,
        });
    }

    let first_seen = ps.first_seen_at.unwrap_or(now);
    let elapsed_first = now.duration_since(first_seen).ok().map(|d| d.as_secs());
    let elapsed_hs = ps
        .last_handshake
        .and_then(|t| now.duration_since(t).ok())
        .map(|d| d.as_secs());

    debug!(
        "health-check: processing active peer: peer={}, \
         elapsed_since_first_seen={:?}, elapsed_since_last_handshake={:?}",
        ps.config.name, elapsed_first, elapsed_hs,
    );

    // No handshake yet — apply the connection-deadline timer.
    if ps.last_handshake.is_none() {
        return super::timeouts::check_first_handshake_timeout(ps, now, first_hs_timeout);
    }

    // Handshake captured — apply the idle watchdog.
    super::timeouts::check_idle_timeout(ps, now, idle_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DesiredState;
    use crate::test_fixtures::*;

    /// Regression: process_one_peer records first_seen_at on initial encounter.
    #[tokio::test]
    async fn test_process_one_peer_marks_first_seen_on_first_encounter() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let peer = defguard_wireguard_rs::peer::Peer::new(key);

        let before = SystemTime::now();
        process_one_peer(
            &mut ps,
            &peer,
            before,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // No event — peer is still pending.
        assert!(ps.first_seen_at.is_some());
        assert!(ps.last_handshake.is_none());
    }

    #[tokio::test]
    async fn test_session_idle_triggers_disable() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.first_seen_at = Some(SystemTime::now());

        // Build a peer with a stale handshake (5 minutes ago).
        let now = std::time::SystemTime::now();
        let elapsed = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        let hs_time = std::time::UNIX_EPOCH + elapsed - Duration::from_secs(300);

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        peer.last_handshake = Some(hs_time);

        let before = SystemTime::now();
        process_one_peer(
            &mut ps,
            &peer,
            before,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Peer was auto-disabled.
        assert_eq!(ps.desired, DesiredState::Disabled);
    }

    /// Regression: kernel reports `last_handshake = UNIX_EPOCH` (zero wrapped)
    /// when no handshake has occurred. The timeout must be driven by our own
    /// `first_seen_at` observation time, not the kernel's bogus timestamp.
    ///
    /// Without the fix (using kernel `last_handshake`), `elapsed_since_handshake`
    /// computes to ~1.7 billion seconds and triggers an immediate timeout.
    /// With the fix, the timeout counts from `first_seen_at`, so a peer seen
    /// recently stays enabled until our own threshold is exceeded.
    #[tokio::test]
    async fn test_timeout_uses_first_seen_at_not_kernel_handshake() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        // We observed the peer 10 seconds ago.
        let first_seen = SystemTime::now() - Duration::from_secs(10);
        ps.first_seen_at = Some(first_seen);

        // Kernel says last handshake was at UNIX_EPOCH (the lib-wrapped-zero
        // quirk — real value when no handshake ever occurred).
        let bogus_kernel_hs = std::time::SystemTime::UNIX_EPOCH;

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        peer.last_handshake = Some(bogus_kernel_hs);

        // Advance time to 70 seconds after we first saw the peer (well past
        // the 60-second timeout threshold).
        let now = first_seen + Duration::from_secs(70);

        process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Peer should be disabled because 70s > 60s threshold measured from
        // first_seen_at, not from the bogus kernel timestamp.
        assert_eq!(ps.desired, DesiredState::Disabled);
    }

    /// First-handshake timeout triggers disable AND returns a Timeout notification.
    #[tokio::test]
    async fn test_first_handshake_timeout_returns_notification() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        // Observed 70 seconds ago (past the 60s threshold).
        let first_seen = SystemTime::now() - Duration::from_secs(70);
        ps.first_seen_at = Some(first_seen);

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let peer = defguard_wireguard_rs::peer::Peer::new(key);
        let now = first_seen + Duration::from_secs(70);

        let event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Should be disabled.
        assert_eq!(ps.desired, DesiredState::Disabled);
        // Should return a Timeout notification.
        let ev = event.expect("expected timeout notification");
        assert_eq!(
            ev.kind,
            NotificationKind::FirstHandshakeTimeout { elapsed_secs: 60 }
        );
    }

    /// Transition from no-handshake to handshake returns one ConnectionEstablished
    /// notification. Subsequent calls with the same handshake do NOT re-notify.
    #[tokio::test]
    async fn test_connection_established_notifies_once() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;
        let now = SystemTime::now();
        ps.first_seen_at = Some(now - Duration::from_secs(10));

        // First call: no handshake yet → no notification.
        let key1 = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let peer1 = defguard_wireguard_rs::peer::Peer::new(key1);
        let evt1 = process_one_peer(
            &mut ps,
            &peer1,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;
        assert!(evt1.is_none());

        // Second call: handshake arrives → one notification.
        let key2 = defguard_wireguard_rs::key::Key::new([2u8; 32]);
        let mut peer2 = defguard_wireguard_rs::peer::Peer::new(key2);
        peer2.last_handshake = Some(now - Duration::from_secs(5));
        let evt2 = process_one_peer(
            &mut ps,
            &peer2,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;
        let evt2 = evt2.expect("expected connection established notification");
        assert_eq!(evt2.kind, NotificationKind::ConnectionEstablished);

        // Third call: still same handshake → no more notifications.
        let key3 = defguard_wireguard_rs::key::Key::new([3u8; 32]);
        let mut peer3 = defguard_wireguard_rs::peer::Peer::new(key3);
        peer3.last_handshake = Some(now - Duration::from_secs(5));
        let evt3 = process_one_peer(
            &mut ps,
            &peer3,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;
        assert!(evt3.is_none());
    }

    /// Idle timeout uses last_handshake specifically, NOT first_seen_at.
    /// A peer first seen 300s ago but with a handshake 50s ago should NOT be
    /// considered idle (50 < 180).
    #[tokio::test]
    async fn test_idle_uses_last_handshake_not_first_seen() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        // Observed long ago...
        let first_seen = SystemTime::now() - Duration::from_secs(300);
        ps.first_seen_at = Some(first_seen);

        // But handshaked recently (50s ago).
        let hs_time = SystemTime::now() - Duration::from_secs(50);
        ps.last_handshake = Some(hs_time);

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let peer = defguard_wireguard_rs::peer::Peer::new(key);
        let now = SystemTime::now();

        let event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Should NOT be disabled — last_handshake is recent.
        assert_eq!(ps.desired, DesiredState::Enabled);
        // No notification — within idle window.
        assert!(event.is_none());
    }

    /// Idle timeout DOES trigger when last_handshake is stale (> 180s), even if
    /// first_seen_at is recent.
    #[tokio::test]
    async fn test_idle_triggers_on_stale_handshake() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        // Handshake 200s ago (past idle threshold).
        let hs_time = SystemTime::now() - Duration::from_secs(200);
        ps.last_handshake = Some(hs_time);

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let peer = defguard_wireguard_rs::peer::Peer::new(key);
        let now = SystemTime::now();

        let event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Should be disabled.
        assert_eq!(ps.desired, DesiredState::Disabled);
        // Should return an IdleDisconnected notification.
        let ev = event.expect("expected idle disconnected notification");
        assert_eq!(ev.kind, NotificationKind::IdleDisconnected);
    }

    /// Bogs kernel timestamp (UNIX_EPOCH) does not flip peer into post-handshake
    /// mode. The peer stays in pre-handshake phase and uses first_seen_at.
    #[tokio::test]
    async fn test_bogus_kernel_timestamp_does_not_flip_phase() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        // Observed 70s ago (past first-handshake threshold).
        let first_seen = SystemTime::now() - Duration::from_secs(70);
        ps.first_seen_at = Some(first_seen);

        // Kernel reports UNIX_EPOCH (bogus zero-wrap).
        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        peer.last_handshake = Some(SystemTime::UNIX_EPOCH);

        let now = first_seen + Duration::from_secs(70);
        let event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Should be disabled via first-handshake timeout.
        assert_eq!(ps.desired, DesiredState::Disabled);
        let ev = event.expect("expected timeout notification");
        assert_eq!(
            ev.kind,
            NotificationKind::FirstHandshakeTimeout { elapsed_secs: 60 }
        );
        // last_handshake should remain None (bogus value filtered out).
        assert!(ps.last_handshake.is_none());
    }

    /// Regression: peer completes first handshake on initial encounter.
    /// first_seen_at must still be recorded so the timeout counter starts
    /// from the correct reference point, not from `now`.
    #[tokio::test]
    async fn test_first_seen_set_even_when_handshake_arrives_immediately() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        peer.last_handshake = Some(SystemTime::now() - Duration::from_secs(2));

        let now = SystemTime::now();
        let event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // first_seen_at must be recorded (not None).
        assert!(ps.first_seen_at.is_some(), "first_seen_at should be set");

        // Connection established notification should fire.
        let evt = event.expect("expected connection established notification");
        assert_eq!(evt.kind, NotificationKind::ConnectionEstablished);

        // Peer should still be enabled (handshake was recent, no idle/timeout).
        assert_eq!(ps.desired, DesiredState::Enabled);
    }

    /// Regression: debug-log time deltas read from the `now` argument, not a
    /// fresh SystemTime::now(), so they stay stable across repeated polls.
    #[tokio::test]
    async fn test_debug_log_uses_passed_now_not_system_time() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        let first_seen = SystemTime::now() - Duration::from_secs(100);
        ps.first_seen_at = Some(first_seen);
        let hs_time = SystemTime::now() - Duration::from_secs(30);
        ps.last_handshake = Some(hs_time);

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let peer = defguard_wireguard_rs::peer::Peer::new(key);
        let now = SystemTime::now();

        // process_one_peer must not panic and must preserve state when
        // both timers are within their thresholds.
        let _event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // State should remain healthy (no timeout/idle triggered).
        assert_eq!(ps.desired, DesiredState::Enabled);
        // first_seen_at and last_handshake should be preserved.
        assert_eq!(ps.first_seen_at, Some(first_seen));
        assert_eq!(ps.last_handshake, Some(hs_time));
    }

    /// Regression: once first_seen_at is recorded, subsequent polls do NOT
    /// reset it (only reconcile success or disable paths should reset it).
    #[tokio::test]
    async fn test_first_seen_not_reset_by_normal_polls() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        let original_first_seen = SystemTime::now() - Duration::from_secs(50);
        ps.first_seen_at = Some(original_first_seen);
        ps.last_handshake = Some(SystemTime::now() - Duration::from_secs(10));

        let now = SystemTime::now();

        // Simulate three consecutive polls.
        for i in 0..3 {
            let key = defguard_wireguard_rs::key::Key::new([i as u8; 32]);
            let peer = defguard_wireguard_rs::peer::Peer::new(key);
            let _ = process_one_peer(
                &mut ps,
                &peer,
                now,
                Duration::from_secs(60),
                Duration::from_secs(180),
            )
            .await;
        }

        // first_seen_at should still hold its original value.
        assert_eq!(ps.first_seen_at, Some(original_first_seen));
        // Peer should still be enabled.
        assert_eq!(ps.desired, DesiredState::Enabled);
    }

    /// Regression: stale last_handshake from a previous session doesn't block
    /// the ConnectionEstablished notification on re-enable.
    #[tokio::test]
    async fn test_stale_last_handshake_doesnt_block_connection_notification_on_re_enable() {
        let mut ps = make_peer_state("alice", "10.0.0.2/32", ALICE_ID);
        ps.desired = DesiredState::Enabled;

        // Simulate stale last_handshake from a previous session (10 minutes ago).
        let stale_hs = SystemTime::now() - Duration::from_secs(600);
        ps.last_handshake = Some(stale_hs);

        // Re-enable: reset last_handshake so the next poll can detect the transition.
        ps.last_handshake = None;

        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        peer.last_handshake = Some(SystemTime::now() - Duration::from_secs(5));

        let now = SystemTime::now();
        let event = process_one_peer(
            &mut ps,
            &peer,
            now,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await;

        // Connection established notification should fire (transition detected).
        let evt = event.expect("expected connection established notification");
        assert_eq!(evt.kind, NotificationKind::ConnectionEstablished);

        // Peer should still be enabled.
        assert_eq!(ps.desired, DesiredState::Enabled);
    }

    /// Health checks skip disabled peers entirely — only enabled+present peers
    /// enter the processing pipeline.
    #[tokio::test]
    async fn test_health_checks_skip_disabled_peers() {
        use super::super::types::PollSnapshot;

        let mut state = crate::state::SystemState::from_config(crate::config::VpnConfig {
            interface_name: "wg0".into(),
            peers: vec![
                crate::config::PeerConfig {
                    telegram_id: ALICE_ID,
                    name: "alice".into(),
                    allowed_ips: "10.0.0.2/32".into(),
                    public_key: defguard_wireguard_rs::key::Key::new([1u8; 32]).to_string(),
                },
                crate::config::PeerConfig {
                    telegram_id: BOB_ID,
                    name: "bob".into(),
                    allowed_ips: "10.0.0.3/32".into(),
                    public_key: defguard_wireguard_rs::key::Key::new([2u8; 32]).to_string(),
                },
            ],
            ..Default::default()
        });

        // Alice is enabled; Bob is disabled.
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        // Snapshot has both peers present (matching their configured pubkeys).
        let alice_key: defguard_wireguard_rs::key::Key = state.peers[0]
            .config
            .public_key
            .as_str()
            .try_into()
            .unwrap();
        let bob_key: defguard_wireguard_rs::key::Key = state.peers[1]
            .config
            .public_key
            .as_str()
            .try_into()
            .unwrap();
        let now = SystemTime::now();
        let mut alice_peer = defguard_wireguard_rs::peer::Peer::new(alice_key);
        alice_peer.last_handshake = Some(now - Duration::from_secs(5));
        let mut bob_peer = defguard_wireguard_rs::peer::Peer::new(bob_key);
        // Bob's handshake is stale — would trigger idle if he were enabled.
        bob_peer.last_handshake = Some(now - Duration::from_secs(300));
        let snapshot = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![alice_peer, bob_peer],
            routes: vec![],
        };

        let events = run_health_checks(
            &mut state,
            &snapshot,
            &Duration::from_secs(60),
            &Duration::from_secs(180),
        )
        .await;

        // Only Alice's events could appear (Bob is disabled → skipped).
        for ev in &events {
            assert_eq!(ev.user_id, ALICE_ID, "Bob must not generate events");
        }
    }

    /// Health checks also skip enabled peers that are NOT on the interface —
    /// reconcile will handle them, so there is nothing to assess yet.
    #[tokio::test]
    async fn test_health_checks_skip_enabled_but_absent_peers() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        // Empty snapshot — peer is not on interface.
        let snapshot = super::super::types::PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![],
            routes: vec![],
        };

        let events = run_health_checks(
            &mut state,
            &snapshot,
            &Duration::from_secs(60),
            &Duration::from_secs(180),
        )
        .await;

        assert!(
            events.is_empty(),
            "enabled-but-absent peer should produce no events"
        );
    }
}
