//! Per-peer timeout checks.
//!
//! Two independent watchdog timers run on every poll while a peer is enabled:
//!
//! 1. **Connection deadline** ([`check_first_handshake_timeout`]) — counts
//!    elapsed seconds since [`PeerState::first_seen_at`]. If no handshake
//!    arrives within the configured window (default 60 s, configurable via
//!    `vpn.first_handshake_timeout`), the peer is auto-disabled and the user
//!    receives a [`NotificationKind::FirstHandshakeTimeout`] notification.
//!
//! 2. **Idle watchdog** ([`check_idle_timeout`]) — counts elapsed seconds
//!    since [`PeerState::last_handshake`]. If the session goes quiet past the
//!    hard-coded 180 s threshold, the peer is auto-disabled and the user
//!    receives a [`NotificationKind::IdleDisconnected`] notification.
//!
//! Both timers read from `PeerState`, never from the kernel directly, so they
//! are immune to lib-wg quirks around `last_handshake` reporting.

use std::time::{Duration, SystemTime};

use tracing::info;

use crate::state::*;

use super::types::*;

/// Connection-deadline timer.
///
/// Counts elapsed seconds since [`PeerState::first_seen_at`]. Fires when the
/// configured window elapses without a successful handshake, at which point
/// the peer is auto-disabled and a [`NotificationKind::FirstHandshakeTimeout`]
/// event is returned.
///
/// Driven from `first_seen_at` rather than the kernel-reported
/// `last_handshake` because lib-wg wraps "no handshake" into `UNIX_EPOCH`,
/// which would otherwise fire immediately.
pub(crate) fn check_first_handshake_timeout(
    ps: &mut PeerState,
    now: SystemTime,
    first_hs_timeout: Duration,
) -> Option<NotificationEvent> {
    let first_seen = ps.first_seen_at?;
    let elapsed_secs = now.duration_since(first_seen).ok()?.as_secs();

    if elapsed_secs >= first_hs_timeout.as_secs() {
        info!(
            "first-handshake timeout exceeded: peer={}, elapsed_secs={}",
            ps.config.name, elapsed_secs
        );
        ps.first_seen_at = None;
        ps.last_handshake = None;
        ps.desired = DesiredState::Disabled;

        Some(NotificationEvent {
            user_id: ps.config.telegram_id,
            peer_name: ps.config.name.clone(),
            kind: NotificationKind::FirstHandshakeTimeout {
                elapsed_secs: first_hs_timeout.as_secs(),
            },
        })
    } else {
        None
    }
}

/// Idle-watchdog timer.
///
/// Counts elapsed seconds since [`PeerState::last_handshake`]. Fires when the
/// session has been quiet for longer than the threshold (hard-coded 180 s),
/// at which point the peer is auto-disabled and a
/// [`NotificationKind::IdleDisconnected`] event is returned.
pub(crate) fn check_idle_timeout(
    ps: &mut PeerState,
    now: SystemTime,
    idle_timeout: Duration,
) -> Option<NotificationEvent> {
    let last_handshake = ps.last_handshake?;
    let idle_elapsed = now.duration_since(last_handshake).ok()?.as_secs();

    if idle_elapsed >= idle_timeout.as_secs() {
        info!(
            "session idle timeout exceeded: peer={}, idle_elapsed={}s",
            ps.config.name, idle_elapsed
        );
        ps.first_seen_at = None;
        ps.last_handshake = None;
        ps.desired = DesiredState::Disabled;

        Some(NotificationEvent {
            user_id: ps.config.telegram_id,
            peer_name: ps.config.name.clone(),
            kind: NotificationKind::IdleDisconnected,
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::*;

    /// Build a peer state pre-populated for timeout testing.
    fn healthy_peer(name: &str, cidr: &str, id: i64) -> PeerState {
        let mut ps = make_peer_state(name, cidr, id);
        ps.desired = DesiredState::Enabled;
        ps.first_seen_at = Some(SystemTime::now() - Duration::from_secs(10));
        ps.last_handshake = Some(SystemTime::now() - Duration::from_secs(5));
        ps
    }

    // --- check_first_handshake_timeout ---

    /// No timeout when the peer was observed recently.
    #[test]
    fn test_first_handshake_timeout_not_fired_when_recent() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        let now = ps.first_seen_at.unwrap() + Duration::from_secs(30);
        let result = check_first_handshake_timeout(&mut ps, now, Duration::from_secs(60));
        assert!(result.is_none());
    }

    /// Timeout fires exactly when elapsed exceeds the threshold.
    #[test]
    fn test_first_handshake_timeout_fires_at_threshold() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        let now = ps.first_seen_at.unwrap() + Duration::from_secs(61);
        let event = check_first_handshake_timeout(&mut ps, now, Duration::from_secs(60));
        let ev = event.expect("expected timeout event");
        assert_eq!(
            ev.kind,
            NotificationKind::FirstHandshakeTimeout { elapsed_secs: 60 }
        );
        assert_eq!(ev.peer_name, "alice");
        assert_eq!(ev.user_id, ALICE_ID);
        assert_eq!(ps.desired, DesiredState::Disabled);
    }

    /// Missing first_seen_at short-circuits to None.
    #[test]
    fn test_first_handshake_timeout_skips_without_first_seen() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        ps.first_seen_at = None;
        let result =
            check_first_handshake_timeout(&mut ps, SystemTime::now(), Duration::from_secs(60));
        assert!(result.is_none());
    }

    /// Clears both timers when timeout fires.
    #[test]
    fn test_first_handshake_timeout_clears_timers_on_fire() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        let now = ps.first_seen_at.unwrap() + Duration::from_secs(120);
        check_first_handshake_timeout(&mut ps, now, Duration::from_secs(60));
        assert!(ps.first_seen_at.is_none());
        assert!(ps.last_handshake.is_none());
    }

    /// The timeout value reported in the event matches the configured threshold,
    /// not the actual elapsed time.
    #[test]
    fn test_first_handshake_timeout_reports_configured_threshold_not_actual() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        let now = ps.first_seen_at.unwrap() + Duration::from_secs(90);
        let event = check_first_handshake_timeout(&mut ps, now, Duration::from_secs(60));
        let ev = event.expect("expected timeout event");
        match ev.kind {
            NotificationKind::FirstHandshakeTimeout { elapsed_secs } => {
                assert_eq!(elapsed_secs, 60, "should report configured threshold");
            }
            _ => panic!("wrong notification kind"),
        }
    }

    // --- check_idle_timeout ---

    /// No timeout when the session is still active.
    #[test]
    fn test_idle_timeout_not_fired_when_active() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        let now = SystemTime::now();
        let result = check_idle_timeout(&mut ps, now, Duration::from_secs(180));
        assert!(result.is_none());
    }

    /// Timeout fires when idle period exceeds threshold.
    #[test]
    fn test_idle_timeout_fires_when_stale() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        ps.last_handshake = Some(SystemTime::now() - Duration::from_secs(200));
        let now = SystemTime::now();
        let event = check_idle_timeout(&mut ps, now, Duration::from_secs(180));
        let ev = event.expect("expected idle event");
        assert_eq!(ev.kind, NotificationKind::IdleDisconnected);
        assert_eq!(ps.desired, DesiredState::Disabled);
    }

    /// Missing last_handshake short-circuits to None.
    #[test]
    fn test_idle_timeout_skips_without_last_handshake() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        ps.last_handshake = None;
        let result = check_idle_timeout(&mut ps, SystemTime::now(), Duration::from_secs(180));
        assert!(result.is_none());
    }

    /// Clears both timers when idle timeout fires.
    #[test]
    fn test_idle_timeout_clears_timers_on_fire() {
        let mut ps = healthy_peer("alice", "10.0.0.2/32", ALICE_ID);
        ps.last_handshake = Some(SystemTime::now() - Duration::from_secs(200));
        check_idle_timeout(&mut ps, SystemTime::now(), Duration::from_secs(180));
        assert!(ps.first_seen_at.is_none());
        assert!(ps.last_handshake.is_none());
    }
}
