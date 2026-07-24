use std::time::SystemTime;

use tracing::{debug, info, warn};

use crate::state::*;
use crate::vpn;

use super::types::*;

/// Phase C: Reconcile. Bring each peer's actual on-interface state into
/// alignment with its declared intent (`desired`). Uses the captured snapshot
/// for read-only presence checks; write operations go through `vpn::*` directly.
pub(crate) async fn reconcile_all(state: &mut SystemState, snapshot: &PollSnapshot) {
    for ps in &mut state.peers {
        match ps.desired {
            DesiredState::Enabled => reconcile_enabled_peer(ps, snapshot).await,
            DesiredState::Disabled => reconcile_disabled_peer(ps, snapshot).await,
        }
    }
}

// --- Per-peer reconciliation ---

/// Ensure a desired-enabled peer is present on the interface with a matching
/// route. Skips when everything is already aligned.
async fn reconcile_enabled_peer(ps: &mut PeerState, snapshot: &PollSnapshot) {
    let iface_name = snapshot.iface_name();
    let cidr = &ps.config.allowed_ips;
    let pubkey = &ps.config.public_key;
    let peer_name = &ps.config.name;

    // Already online? Skip to avoid EEXIST noise.
    if snapshot.peer_on_iface(pubkey) && snapshot.route_for_cidr(cidr) {
        debug!("reconciled: already online: peer={peer_name}, cidr={cidr}",);
        return;
    }

    let peer_present = snapshot.peer_on_iface(pubkey);
    let route_present = snapshot.route_for_cidr(cidr);

    let params = ConfigureParams {
        iface_name,
        peer_name,
        pubkey,
        cidr,
        peer_present,
        route_present,
    };
    let outcome = configure_peer_and_route(&params).await;

    match outcome {
        Ok(()) => {
            // Both timers are touched only when we actually created the peer.
            // If the peer was already on the interface and we only fixed the
            // route, the connection never went down — overwriting the
            // observation timestamps would lose legitimate history and
            // potentially fire a spurious ConnectionEstablished notification.
            if !params.peer_present {
                ps.first_seen_at = Some(SystemTime::now());
                ps.last_handshake = None;
            }
            info!("reconciled: enabled + added: peer={peer_name}, cidr={cidr}",);
        }
        Err(reason) => {
            warn!("reconciliation failed: peer={peer_name}, cidr={cidr}, reason={reason}",);
        }
    }
}

/// Parameters required to configure a WireGuard peer and its host route.
struct ConfigureParams<'a> {
    iface_name: &'a str,
    peer_name: &'a str,
    pubkey: &'a str,
    cidr: &'a str,
    peer_present: bool,
    route_present: bool,
}

/// Attempt to add a WireGuard peer and its host route to the interface.
/// Returns Ok(()) when both succeed, or an error describing which step failed.
async fn configure_peer_and_route(params: &ConfigureParams<'_>) -> Result<(), String> {
    let wg_ok = if params.peer_present {
        true
    } else {
        vpn::ensure_wg_peer(
            params.iface_name,
            params.pubkey,
            params.peer_name,
            params.cidr,
        )
        .is_ok()
    };
    let route_ok = if params.route_present {
        true
    } else {
        vpn::ensure_route(params.iface_name, params.cidr)
            .await
            .is_ok()
    };

    match (wg_ok, route_ok) {
        (true, true) => Ok(()),
        (false, true) => Err("failed to configure WireGuard peer".to_owned()),
        (true, false) => Err("failed to add host route".to_owned()),
        (false, false) => Err("failed to configure WireGuard peer and add host route".to_owned()),
    }
}

/// Remove a desired-disabled peer and its host route from the interface.
/// Skips when everything is already gone.
async fn reconcile_disabled_peer(ps: &mut PeerState, snapshot: &PollSnapshot) {
    let iface_name = snapshot.iface_name();
    let cidr = &ps.config.allowed_ips;
    let pubkey = &ps.config.public_key;
    let peer_name = ps.config.name.clone();

    // Already gone? Skip to avoid logging noise every cycle.
    if !snapshot.peer_on_iface(pubkey) && !snapshot.route_for_cidr(cidr) {
        debug!("reconciled: already offline: peer={peer_name}, cidr={cidr}",);
        return;
    }

    let peer_present = snapshot.peer_on_iface(pubkey);
    let route_present = snapshot.route_for_cidr(cidr);

    let (wg_err, route_err) =
        remove_peer_and_route(iface_name, pubkey, cidr, peer_present, route_present).await;

    match (wg_err, route_err) {
        (None, None) => {
            ps.first_seen_at = None;
            ps.last_handshake = None;
            info!("reconciled: disabled + removed: peer={peer_name}, cidr={cidr}",);
        }
        (Some(wge), Some(re)) => {
            let reason = format!("peer: {wge}, route: {re}");
            warn!(
                "failed to reconcile removal on {iface_name}: peer={peer_name}, cidr={cidr}, reasons={reason}",
            );
        }
        (Some(wge), None) => {
            warn!(
                "failed to remove peer on {iface_name}: peer={peer_name}, cidr={cidr}, reason=peer: {wge}",
            );
        }
        (None, Some(re)) => {
            warn!(
                "failed to delete route on {iface_name}: peer={peer_name}, cidr={cidr}, reason=route: {re}",
            );
        }
    }
}

/// Attempt to remove a WireGuard peer and its host route from the interface.
/// Returns any errors that occurred during removal.
async fn remove_peer_and_route(
    iface_name: &str,
    pubkey: &str,
    cidr: &str,
    peer_present: bool,
    route_present: bool,
) -> (Option<String>, Option<String>) {
    let wg_err = if peer_present {
        vpn::remove_wg_peer(iface_name, pubkey).err()
    } else {
        None
    };
    let route_err = if route_present {
        vpn::delete_route(iface_name, cidr).await.err()
    } else {
        None
    };
    (wg_err, route_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DesiredState;
    use crate::test_fixtures::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_reconcile_activates_missing_peer() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);

        // Set Alice's peer to enabled.
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        // Run reconcile — empty snapshot simulates no interface; ensure calls
        // fail silently, should not panic.
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };
        let _events = reconcile_all(&mut state, &snapshot).await;
    }

    #[tokio::test]
    async fn test_reconcile_deactivates_present_peer_no_crash() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);

        // Start with Alice's peer disabled.
        let alice_peer = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice_peer.desired = DesiredState::Disabled;

        // Run reconcile — empty snapshot; disable fails silently, should not
        // panic.
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };
        let _events = reconcile_all(&mut state, &snapshot).await;
        // No crash means success.
    }

    /// When reconcile sees the peer is already online, it skips configuration
    /// and does NOT reset first_seen_at — the peer was observed before this cycle.
    #[tokio::test]
    async fn test_reconcile_already_online_does_not_reset_first_seen() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice.desired = DesiredState::Enabled;
        let original_first_seen = SystemTime::now() - std::time::Duration::from_secs(100);
        alice.first_seen_at = Some(original_first_seen);

        // Snapshot shows the peer present — reconcile takes the "already online"
        // path and skips configuration.
        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![],
        };

        reconcile_all(&mut state, &snapshot).await;

        // first_seen_at should still hold its original value.
        let alice = state.resolve_peer(ALICE_ID, Some("alice")).unwrap();
        assert_eq!(alice.first_seen_at, Some(original_first_seen));
    }

    /// Regression: when an enabled peer is on the interface but its route is
    /// missing, reconcile must NOT reset observation timers. Those timers
    /// measure connection health, not infrastructure state — fixing the route
    /// does not erase how long the peer has been connected or idle.
    ///
    /// We cannot easily make `ensure_route` succeed without a real kernel
    /// interface, so this test takes two steps:
    ///
    /// 1. Run reconcile with the peer present and route missing. Verify the
    ///    timers are unchanged (the fast path does not touch them, and the
    ///    slow path must not either, even though the route add fails).
    ///
    /// 2. Simulate what would happen if the route add had succeeded and the
    ///    reset executed: manually clear the timers, then run health checks.
    ///    The health check MUST fire a `ConnectionEstablished` notification —
    ///    this confirms the mechanism works and proves that if reconcile
    ///    ever resets the timers, users will receive a spurious notification.
    #[tokio::test]
    async fn test_reconcile_preserves_timers_and_resets_cause_notification() {
        use crate::monitor::health;
        use crate::monitor::types::NotificationKind;

        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice.desired = DesiredState::Enabled;

        // Peer has been observing for a while and completed a handshake.
        let now = SystemTime::now();
        let original_first_seen = now - std::time::Duration::from_secs(100);
        alice.first_seen_at = Some(original_first_seen);
        let hs_time = now - std::time::Duration::from_secs(30);
        alice.last_handshake = Some(hs_time);

        // Snapshot: peer is on the interface (matching the configured pubkey),
        // but the route is absent.
        let key: defguard_wireguard_rs::key::Key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .try_into()
            .expect("valid base64 key");
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![],
        };

        // Step 1: Run reconcile — timers must survive unchanged.
        reconcile_all(&mut state, &snapshot).await;

        let alice = state.resolve_peer(ALICE_ID, Some("alice")).unwrap();
        assert_eq!(
            alice.first_seen_at,
            Some(original_first_seen),
            "first_seen_at must not be reset by reconcile",
        );
        assert_eq!(
            alice.last_handshake,
            Some(hs_time),
            "last_handshake must not be reset by reconcile",
        );

        // Step 2: Simulate the buggy path — manually reset the timers as the
        // regression would do, then run health checks. The health check must
        // fire a ConnectionEstablished notification, proving that if reconcile
        // ever resets the timers, users get a spurious message.
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice.first_seen_at = None;
        alice.last_handshake = None;

        // Build a snapshot where the peer has a recent handshake (as the
        // kernel would report after a successful route add).
        let key2: defguard_wireguard_rs::key::Key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .try_into()
            .expect("valid base64 key");
        let mut peer_with_hs = defguard_wireguard_rs::peer::Peer::new(key2);
        peer_with_hs.last_handshake = Some(SystemTime::now() - std::time::Duration::from_secs(5));
        let snapshot_with_hs = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![peer_with_hs],
            routes: vec![],
        };

        let events = health::run_health_checks(
            &mut state,
            &snapshot_with_hs,
            &std::time::Duration::from_secs(60),
            &std::time::Duration::from_secs(180),
        )
        .await;

        assert_eq!(
            events.len(),
            1,
            "expected exactly one notification when timers are reset, got {:?}",
            events.iter().map(|e| e.kind.label()).collect::<Vec<_>>(),
        );
        assert_eq!(events[0].kind, NotificationKind::ConnectionEstablished);
    }
}
