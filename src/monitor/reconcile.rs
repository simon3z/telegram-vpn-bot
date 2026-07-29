use std::time::SystemTime;

use tracing::{debug, info, warn};

use crate::state::*;
use crate::vpn;

use super::types::*;

/// Phase C: Reconcile. Bring each peer's actual on-interface state into
/// alignment with its declared intent (`desired`). Uses the captured snapshot
/// for read-only presence checks; write operations go through the VPN trait.
pub(crate) async fn reconcile_all(
    state: &mut SystemState,
    snapshot: &PollSnapshot,
    ops: &(dyn vpn::WireGuardOps + Send + Sync),
) {
    for ps in &mut state.peers {
        match ps.desired {
            DesiredState::Enabled => reconcile_enabled_peer(ps, snapshot, ops).await,
            DesiredState::Disabled => reconcile_disabled_peer(ps, snapshot, ops).await,
        }
    }
}

// --- Per-peer reconciliation ---

/// Ensure a desired-enabled peer is present on the interface with a matching
/// route. Skips when everything is already aligned.
async fn reconcile_enabled_peer(
    ps: &mut PeerState,
    snapshot: &PollSnapshot,
    ops: &(dyn vpn::WireGuardOps + Send + Sync),
) {
    let iface_name = snapshot.iface_name();
    let cidr = &ps.config.allowed_ips;
    let pubkey = &ps.config.public_key;
    let peer_name = &ps.config.name;

    // Already online? Skip to avoid EEXIST noise.
    if snapshot.peer_on_iface(pubkey) && snapshot.route_for_cidr(cidr) {
        debug!("reconciled: already online: peer={peer_name}, cidr={cidr}");
        return;
    }

    let peer_present = snapshot.peer_on_iface(pubkey);
    let route_present = snapshot.route_for_cidr(cidr);

    let outcome = configure_peer_and_route(
        ops,
        iface_name,
        peer_name,
        pubkey,
        cidr,
        peer_present,
        route_present,
    )
    .await;

    match outcome {
        Ok(()) => {
            // Both timers are touched only when we actually created the peer.
            // If the peer was already on the interface and we only fixed the
            // route, the connection never went down — overwriting the
            // observation timestamps would lose legitimate history and
            // potentially fire a spurious ConnectionEstablished notification.
            if !peer_present {
                ps.first_seen_at = Some(SystemTime::now());
                ps.last_handshake = None;
            }
            info!("reconciled: enabled + added: peer={peer_name}, cidr={cidr}");
        }
        Err(reason) => {
            warn!("reconciliation failed: peer={peer_name}, cidr={cidr}, reason={reason}");
        }
    }
}

/// Attempt to add a WireGuard peer and its host route to the interface.
/// Returns Ok(()) when both succeed, or an error describing which step failed.
async fn configure_peer_and_route(
    ops: &(dyn vpn::WireGuardOps + Send + Sync),
    iface_name: &str,
    peer_name: &str,
    pubkey: &str,
    cidr: &str,
    peer_present: bool,
    route_present: bool,
) -> Result<(), String> {
    let wg_ok = if peer_present {
        true
    } else {
        vpn::ensure_wg_peer(ops, iface_name, pubkey, peer_name, cidr)
            .await
            .is_ok()
    };
    let route_ok = if route_present {
        true
    } else {
        vpn::ensure_route(ops, iface_name, cidr).await.is_ok()
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
async fn reconcile_disabled_peer(
    ps: &mut PeerState,
    snapshot: &PollSnapshot,
    ops: &(dyn vpn::WireGuardOps + Send + Sync),
) {
    let iface_name = snapshot.iface_name();
    let cidr = &ps.config.allowed_ips;
    let pubkey = &ps.config.public_key;
    let peer_name = ps.config.name.clone();

    // Already gone? Skip to avoid logging noise every cycle.
    if !snapshot.peer_on_iface(pubkey) && !snapshot.route_for_cidr(cidr) {
        debug!("reconciled: already offline: peer={peer_name}, cidr={cidr}");
        return;
    }

    let peer_present = snapshot.peer_on_iface(pubkey);
    let route_present = snapshot.route_for_cidr(cidr);

    let (wg_err, route_err) =
        remove_peer_and_route(ops, iface_name, pubkey, cidr, peer_present, route_present).await;

    match (wg_err, route_err) {
        (None, None) => {
            ps.first_seen_at = None;
            ps.last_handshake = None;
            info!("reconciled: disabled + removed: peer={peer_name}, cidr={cidr}");
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
    ops: &(dyn vpn::WireGuardOps + Send + Sync),
    iface_name: &str,
    pubkey: &str,
    cidr: &str,
    peer_present: bool,
    route_present: bool,
) -> (Option<String>, Option<String>) {
    let wg_err = if peer_present {
        vpn::remove_wg_peer(ops, iface_name, pubkey).await.err()
    } else {
        None
    };
    let route_err = if route_present {
        vpn::delete_route(ops, iface_name, cidr).await.err()
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
    use crate::vpn::TrackedMock;
    use std::time::SystemTime;

    /// Helper: build a snapshot that includes a peer matching the state entry.
    fn snapshot_with_peer(state: &SystemState, idx: usize) -> PollSnapshot {
        let pubkey = &state.peers[idx].config.public_key;
        let key: defguard_wireguard_rs::key::Key = pubkey
            .as_str()
            .try_into()
            .unwrap_or_else(|_| defguard_wireguard_rs::key::Key::new([0u8; 32]));
        PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![],
        }
    }

    /// Helper: build a snapshot with a peer AND a matching route.
    fn snapshot_with_peer_and_route(state: &SystemState, idx: usize) -> PollSnapshot {
        let pubkey = &state.peers[idx].config.public_key;
        let key: defguard_wireguard_rs::key::Key = pubkey
            .as_str()
            .try_into()
            .unwrap_or_else(|_| defguard_wireguard_rs::key::Key::new([0u8; 32]));
        let parsed: std::net::Ipv4Addr = state.peers[idx]
            .config
            .allowed_ips
            .split('/')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("valid CIDR");
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4(parsed), 32)
            .build();
        PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![route],
        }
    }

    /// Regression: missing token field produces a clear error.
    #[tokio::test]
    async fn test_reconcile_activates_missing_peer_empty_snapshot() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        let mock = TrackedMock::new();
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };
        reconcile_all(&mut state, &snapshot, &mock).await;

        // Peer absent + route missing → slow path attempts both operations.
        assert!(
            mock.called_configure_peer(),
            "configure_peer must be called when peer is missing"
        );
        assert!(
            mock.called_add_route(),
            "add_route must be called when route is missing"
        );

        // Timers should be set since we attempted creation.
        assert!(
            state.peers[0].first_seen_at.is_some(),
            "first_seen_at should be set"
        );
    }

    #[tokio::test]
    async fn test_reconcile_deactivates_present_peer_no_crash() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice_peer = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice_peer.desired = DesiredState::Disabled;

        let mock = TrackedMock::new();
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };
        reconcile_all(&mut state, &snapshot, &mock).await;

        // Peer is NOT on interface per snapshot, so no removal needed.
        assert!(!mock.called_remove_peer());
        assert!(!mock.called_delete_route());
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

        // Snapshot has peer AND route matching Alice's configured values.
        let snapshot = snapshot_with_peer_and_route(&state, 0);
        let mock = TrackedMock::new();

        reconcile_all(&mut state, &snapshot, &mock).await;

        // No VPN calls should be made — everything is aligned.
        assert!(!mock.called_configure_peer());
        assert!(!mock.called_add_route());
        assert!(!mock.called_remove_peer());
        assert!(!mock.called_delete_route());

        // first_seen_at should still hold its original value.
        assert_eq!(state.peers[0].first_seen_at, Some(original_first_seen),);
    }

    /// Regression: when an enabled peer is on the interface but its route is
    /// missing, reconcile fixes only the route. It must NOT reset observation
    /// timers — those measure connection health, not infrastructure state.
    #[tokio::test]
    async fn test_reconcile_route_only_fix_calls_add_route_not_configure() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice.desired = DesiredState::Enabled;

        let now = SystemTime::now();
        let original_first_seen = now - std::time::Duration::from_secs(100);
        alice.first_seen_at = Some(original_first_seen);
        let hs_time = now - std::time::Duration::from_secs(30);
        alice.last_handshake = Some(hs_time);

        // Snapshot: peer is on the interface, but route is absent.
        let snapshot = snapshot_with_peer(&state, 0);
        let mock = TrackedMock::new();

        reconcile_all(&mut state, &snapshot, &mock).await;

        // configure_peer must NOT have been called (peer already present).
        assert!(
            !mock.called_configure_peer(),
            "configure_peer must not be called when peer is already on interface"
        );
        // add_route SHOULD have been called (route was missing).
        assert!(
            mock.called_add_route(),
            "add_route must be called when route is missing"
        );

        // Timers must survive unchanged.
        assert_eq!(
            state.peers[0].first_seen_at,
            Some(original_first_seen),
            "first_seen_at must not be reset by reconcile"
        );
        assert_eq!(
            state.peers[0].last_handshake,
            Some(hs_time),
            "last_handshake must not be reset by reconcile"
        );
    }

    /// After reconcile resets last_handshake (on successful peer creation),
    /// the next health check detects the handshake transition and fires
    /// ConnectionEstablished. This verifies the full lifecycle across phases.
    #[tokio::test]
    async fn test_health_check_detects_transition_after_reconcile_reset() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice.desired = DesiredState::Enabled;

        // Simulate reconcile having just created the peer and reset timers.
        alice.first_seen_at = None;
        alice.last_handshake = None;

        // Use Alice's actual configured pubkey so the snapshot matches.
        let alice_pubkey: defguard_wireguard_rs::key::Key = state.peers[0]
            .config
            .public_key
            .as_str()
            .try_into()
            .expect("valid pubkey");
        let mut peer_with_hs = defguard_wireguard_rs::peer::Peer::new(alice_pubkey);
        peer_with_hs.last_handshake = Some(SystemTime::now() - std::time::Duration::from_secs(5));
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![peer_with_hs],
            routes: vec![],
        };

        let events = crate::monitor::health::run_health_checks(
            &mut state,
            &snapshot,
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
        assert_eq!(
            events[0].kind,
            crate::monitor::types::NotificationKind::ConnectionEstablished
        );
    }

    /// Disabled peer present on interface: reconcile removes it via both
    /// remove_peer and delete_route. Timers are cleared.
    #[tokio::test]
    async fn test_reconcile_removes_present_disabled_peer() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice_peer = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice_peer.desired = DesiredState::Disabled;
        alice_peer.first_seen_at = Some(SystemTime::now());
        alice_peer.last_handshake = Some(SystemTime::now());

        let snapshot = snapshot_with_peer_and_route(&state, 0);
        // Pre-populate mock routes so delete_route can find and call through.
        let mut mock = TrackedMock::new();
        let parsed: std::net::Ipv4Addr = state.peers[0]
            .config
            .allowed_ips
            .split('/')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("valid CIDR");
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4(parsed), 32)
            .build();
        mock.push_route(route);

        reconcile_all(&mut state, &snapshot, &mock).await;

        assert!(
            mock.called_remove_peer(),
            "remove_peer must be called for disabled peer on interface"
        );
        assert!(
            mock.called_delete_route(),
            "delete_route must be called for disabled peer's route"
        );

        // Timers should be cleared after removal.
        assert_eq!(state.peers[0].first_seen_at, None);
        assert_eq!(state.peers[0].last_handshake, None);
    }

    /// Multi-peer scenario: Alice enabled+present, Bob enabled+missing, Carol
    /// disabled+present. Verify the correct subset of VPN calls is made.
    #[tokio::test]
    async fn test_reconcile_multi_peer_selective_operations() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        // Add Bob (enabled, absent from interface).
        let bob_cfg = crate::config::PeerConfig {
            telegram_id: 222,
            name: "bob".to_string(),
            allowed_ips: "10.0.0.3/32".to_string(),
            public_key: defguard_wireguard_rs::key::Key::new([2u8; 32]).to_string(),
        };
        state.peers.push(crate::state::PeerState::new(bob_cfg));
        state.set_desired_for_user(222, "bob", DesiredState::Enabled);

        // Add Carol (disabled, present on interface).
        let carol_cfg = crate::config::PeerConfig {
            telegram_id: 333,
            name: "carol".to_string(),
            allowed_ips: "10.0.0.4/32".to_string(),
            public_key: defguard_wireguard_rs::key::Key::new([3u8; 32]).to_string(),
        };
        state.peers.push(crate::state::PeerState::new(carol_cfg));
        state.set_desired_for_user(333, "carol", DesiredState::Disabled);

        // Snapshot: Alice's peer AND Carol's peer are on the interface.
        // Both snapshots have no routes — but for Carol we need the route
        // present in the snapshot so reconcile attempts deletion.
        let carol_pubkey = &state.peers[2].config.public_key;
        let carol_key: defguard_wireguard_rs::key::Key =
            carol_pubkey.as_str().try_into().expect("valid pubkey");
        let carol_cidr = &state.peers[2].config.allowed_ips;
        let carol_ip: std::net::Ipv4Addr = carol_cidr.split('/').next().unwrap().parse().unwrap();
        let carol_route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4(carol_ip), 32)
            .build();

        let mut snapshot = snapshot_with_peer(&state, 0);
        snapshot
            .peers
            .push(defguard_wireguard_rs::peer::Peer::new(carol_key));
        snapshot.routes.push(carol_route.clone());

        let mut mock = TrackedMock::new();
        // Put Carol's route in the mock too so delete_route can locate it.
        mock.push_route(carol_route);

        reconcile_all(&mut state, &snapshot, &mock).await;

        // Alice: peer present, route missing → add_route called, configure_peer NOT.
        assert!(
            mock.called_add_route(),
            "At least one add_route call expected"
        );

        // Bob: enabled + absent → must call configure_peer and add_route.
        assert!(
            mock.called_configure_peer(),
            "Bob must be configured (enabled + missing)"
        );

        // Carol: disabled + present → must call remove_peer and delete_route.
        assert!(
            mock.called_remove_peer(),
            "Carol must be removed (disabled + present)"
        );
        assert!(mock.called_delete_route(), "Carol's route must be deleted");

        // Verify call order: all enables happen before disables (iteration order).
        let history = mock.call_history();
        let last_configure = history.iter().rposition(|c| c.as_str() == "configure_peer");
        let first_remove = history.iter().position(|c| c.as_str() == "remove_peer");
        if let (Some(lc), Some(fr)) = (last_configure, first_remove) {
            assert!(
                lc < fr,
                "all configure_peer calls should precede remove_peer in iteration order"
            );
        }
    }

    /// When VPN writes all fail, reconcile logs warnings but does not panic.
    /// State timers are not modified because the write failed.
    #[tokio::test]
    async fn test_reconcile_handles_write_failures_gracefully() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);
        let original_first_seen = SystemTime::now() - std::time::Duration::from_secs(50);
        state.peers[0].first_seen_at = Some(original_first_seen);

        let mock = TrackedMock::new().with_write_error("simulated kernel error");
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };

        reconcile_all(&mut state, &snapshot, &mock).await;

        // Calls were attempted even though they failed.
        assert!(mock.called_configure_peer());
        assert!(mock.called_add_route());

        // first_seen_at should NOT have been touched — the write failed,
        // so we never actually created the peer.
        assert_eq!(
            state.peers[0].first_seen_at,
            Some(original_first_seen),
            "timers must not change when writes fail"
        );
    }
}
