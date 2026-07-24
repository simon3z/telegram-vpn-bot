pub mod health;
pub mod phases;
pub mod reconcile;
pub mod timeouts;
pub mod types;

pub use types::NotificationEvent;

pub(crate) use phases::spawn_monitor;

#[cfg(test)]
mod tests {
    use super::phases::{run_full_cycle_inner, sync_vpn_connection};
    use super::reconcile::reconcile_all;
    use super::types::PollSnapshot;
    use crate::state::{DesiredState, VpnConnectionState};
    use crate::test_fixtures::*;
    use crate::vpn::TrackedMock;
    use std::time::{Duration, SystemTime};

    #[tokio::test]
    async fn test_reconcile_activates_missing_peer() {
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
            "first_seen_at should be set after activate attempt"
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
        let _events = reconcile_all(&mut state, &snapshot, &mock).await;
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
        let original_first_seen = SystemTime::now() - Duration::from_secs(100);
        alice.first_seen_at = Some(original_first_seen);

        // Build a snapshot whose peer key matches Alice's configured pubkey.
        let pubkey = &state.peers[0].config.public_key;
        let key: defguard_wireguard_rs::key::Key =
            pubkey.as_str().try_into().expect("valid pubkey");
        let cidr_ip: std::net::Ipv4Addr = state.peers[0]
            .config
            .allowed_ips
            .split('/')
            .next()
            .unwrap()
            .parse()
            .expect("valid CIDR");
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4(cidr_ip), 32)
            .build();
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![route],
        };
        let mock = TrackedMock::new();

        reconcile_all(&mut state, &snapshot, &mock).await;

        let alice = state.resolve_peer(ALICE_ID, Some("alice")).unwrap();
        assert_eq!(alice.first_seen_at, Some(original_first_seen));
    }

    /// Regression: when sync detects a connected peer, the VPN connection
    /// state flips from Disconnected to Connected. This drives downstream
    /// decisions like "has the tunnel come up?" that depend on accurate
    /// connection tracking.
    #[tokio::test]
    async fn test_sync_updates_connection_state_when_peer_present_and_handshake_arrives() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.vpn_connection = VpnConnectionState::Disconnected;

        let pubkey = &state.peers[0].config.public_key;
        let key: defguard_wireguard_rs::key::Key =
            pubkey.as_str().try_into().expect("valid pubkey");
        let allowed_ips: Vec<defguard_wireguard_rs::net::IpAddrMask> = state.peers[0]
            .config
            .allowed_ips
            .split(',')
            .filter_map(|cidr| cidr.trim().parse().ok())
            .collect();
        let mut peer_with_hs = defguard_wireguard_rs::peer::Peer::new(key);
        peer_with_hs.allowed_ips = allowed_ips;
        peer_with_hs.last_handshake = Some(SystemTime::now() - Duration::from_secs(5));
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![peer_with_hs],
            routes: vec![],
        };

        crate::monitor::phases::sync_vpn_connection(&mut state, &snapshot);

        match state.vpn_connection {
            VpnConnectionState::Connected { last_handshake } => {
                let elapsed = SystemTime::now()
                    .duration_since(last_handshake)
                    .unwrap_or(Duration::MAX);
                assert!(
                    elapsed < Duration::from_secs(10),
                    "handshake should be recent (~5s ago), got {elapsed:?}"
                );
            }
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    /// When no peer is present OR handshake is missing, VPN stays disconnected.
    /// This covers the guard path that prevents falsely reporting connectivity.
    #[tokio::test]
    async fn test_sync_keeps_disconnected_when_no_peer_present() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.vpn_connection = VpnConnectionState::Disconnected;
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };

        crate::monitor::phases::sync_vpn_connection(&mut state, &snapshot);

        assert!(
            matches!(state.vpn_connection, VpnConnectionState::Disconnected),
            "should stay disconnected when no peers present"
        );
    }

    /// Full-cycle regression: enabled peer absent from interface → sync marks
    /// disconnected, health checks leave desired enabled (no handshake yet),
    /// reconcile calls configure_peer AND add_route. State reflects the
    /// attempted activation.
    #[tokio::test]
    async fn test_full_cycle_activates_missing_peer_through_all_phases() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);
        state.vpn_connection = VpnConnectionState::Disconnected;

        let mock = TrackedMock::new();
        // Snapshot is captured from the mock — empty peers/routes simulate
        // "interface up but no peers configured".

        let events = run_full_cycle_inner(
            &mut state,
            "wg0",
            &Duration::from_secs(60),
            &Duration::from_secs(180),
            &mock,
        )
        .await;

        // Phase A (sync): disconnected because no peer on interface.
        assert!(
            matches!(state.vpn_connection, VpnConnectionState::Disconnected),
            "sync should mark disconnected when no peer present"
        );

        // Phase B (health): no events because peer isn't seen yet — there is
        // nothing to check against.
        assert!(
            events.is_empty(),
            "no health events expected when peer absent from snapshot"
        );

        // Phase C (reconcile): slow path must attempt both operations.
        assert!(
            mock.called_configure_peer(),
            "configure_peer must be called when peer missing"
        );
        assert!(
            mock.called_add_route(),
            "add_route must be called when route missing"
        );

        // Timers should be set since we attempted creation.
        let alice = state.resolve_peer(ALICE_ID, Some("alice")).unwrap();
        assert!(
            alice.first_seen_at.is_some(),
            "first_seen_at must be set after activate attempt"
        );
    }

    /// Multi-phase regression: peer is healthy + present + routed → full cycle
    /// must NOT touch the interface. Sync sets Connected, health returns no
    /// events, reconcile makes zero calls.
    #[tokio::test]
    async fn test_full_cycle_is_noop_when_peer_already_aligned() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        let original_first_seen = SystemTime::now() - Duration::from_secs(100);
        let hs_time = SystemTime::now() - Duration::from_secs(10);
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        alice.first_seen_at = Some(original_first_seen);
        alice.last_handshake = Some(hs_time);

        let pubkey = &state.peers[0].config.public_key;
        let key: defguard_wireguard_rs::key::Key =
            pubkey.as_str().try_into().expect("valid pubkey");
        let cidr_ip: std::net::Ipv4Addr = state.peers[0]
            .config
            .allowed_ips
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4(cidr_ip), 32)
            .build();
        let allowed_ips: Vec<defguard_wireguard_rs::net::IpAddrMask> = state.peers[0]
            .config
            .allowed_ips
            .split(',')
            .filter_map(|cidr| cidr.trim().parse().ok())
            .collect();
        let mut peer_with_hs = defguard_wireguard_rs::peer::Peer::new(key);
        peer_with_hs.allowed_ips = allowed_ips;
        peer_with_hs.last_handshake = Some(hs_time);

        let mock = TrackedMock::new();
        // Pre-populate the mock so PollSnapshot::capture returns our prepared
        // peer and route — simulating a healthy, established connection.
        mock.push_peer(peer_with_hs);
        mock.push_route(route);

        let events = run_full_cycle_inner(
            &mut state,
            "wg0",
            &Duration::from_secs(60),
            &Duration::from_secs(180),
            &mock,
        )
        .await;

        // Phase A: sync flips to Connected.
        assert!(
            matches!(state.vpn_connection, VpnConnectionState::Connected { .. }),
            "sync should flip to Connected when peer + HS present"
        );

        // Phase B: healthy peer → no notifications.
        assert!(
            events.is_empty(),
            "healthy peer should produce no notifications"
        );

        // Phase C: fully aligned → zero VPN calls.
        assert!(!mock.called_configure_peer());
        assert!(!mock.called_add_route());
        assert!(!mock.called_remove_peer());
        assert!(!mock.called_delete_route());

        // Timers preserved — this was observed before this cycle.
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        assert_eq!(alice.first_seen_at, Some(original_first_seen));
        assert_eq!(alice.last_handshake, Some(hs_time));
    }

    /// Re-enable lifecycle: peer was auto-disabled by idle timeout, then
    /// re-enabled via command. Next full cycle must detect DesiredState::Enabled
    /// + absent peer → restore via configure_peer + add_route.
    #[tokio::test]
    async fn test_full_cycle_restores_re_enabled_peer_after_idle_disable() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();

        // Stage 1: peer was seen recently but went idle → auto-disabled.
        alice.first_seen_at = Some(SystemTime::now() - Duration::from_secs(200));
        alice.last_handshake = Some(SystemTime::now() - Duration::from_secs(300));
        alice.desired = DesiredState::Disabled;

        // Simulate user re-enabling via command handler.
        state.set_desired_for_user(ALICE_ID, "alice", DesiredState::Enabled);

        let mock = TrackedMock::new();
        // Mock starts empty — capture will return no peers, simulating the
        // post-disable state where the peer was removed from the interface.

        let events = run_full_cycle_inner(
            &mut state,
            "wg0",
            &Duration::from_secs(60),
            &Duration::from_secs(180),
            &mock,
        )
        .await;

        // Sync: still disconnected (no peer on interface).
        assert!(matches!(
            state.vpn_connection,
            VpnConnectionState::Disconnected
        ));

        // Health: no events — peer isn't in snapshot so there's nothing to assess.
        assert!(events.is_empty());

        // Reconcile: re-enable must attempt restore.
        assert!(
            mock.called_configure_peer(),
            "re-enabled peer must be configured again"
        );
        assert!(
            mock.called_add_route(),
            "re-enabled peer must get its route restored"
        );

        // first_seen_at resets because we're starting fresh post-re-enable.
        let alice = state
            .peers
            .iter_mut()
            .find(|p| p.config.name == "alice")
            .unwrap();
        assert!(
            alice.first_seen_at.is_some(),
            "timer should reset on re-enable"
        );
    }

    // --- PollSnapshot helper method tests ---

    #[test]
    fn test_snapshot_peer_on_iface_matches_by_pubkey() {
        let pubkey_str = "HcxgCdgflJi7UZbhe2PZGx88ri6eFwyBnFv13VCxkXA=";
        let key: defguard_wireguard_rs::key::Key = pubkey_str.try_into().expect("valid pubkey");
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![],
        };
        assert!(snapshot.peer_on_iface(pubkey_str));
        assert!(!snapshot.peer_on_iface("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    #[test]
    fn test_snapshot_peer_on_iface_empty_when_no_peers() {
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };
        assert!(!snapshot.peer_on_iface("anything"));
    }

    #[test]
    fn test_snapshot_route_for_cidr_finds_matching_route() {
        let parsed: std::net::Ipv4Addr = "10.0.0.2".parse().unwrap();
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4(parsed), 32)
            .build();
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![route],
        };
        assert!(snapshot.route_for_cidr("10.0.0.2/32"));
        assert!(!snapshot.route_for_cidr("10.0.0.3/32"));
    }

    #[test]
    fn test_snapshot_route_for_cidr_handles_invalid_cidr_gracefully() {
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![],
            routes: vec![],
        };
        assert!(!snapshot.route_for_cidr("not-a-cidr"));
        assert!(!snapshot.route_for_cidr(""));
    }

    #[test]
    fn test_snapshot_has_any_peer_requires_allowed_ips() {
        let key1 = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let empty_peer = defguard_wireguard_rs::peer::Peer::new(key1);
        let key2 = defguard_wireguard_rs::key::Key::new([2u8; 32]);
        let mut populated_peer = defguard_wireguard_rs::peer::Peer::new(key2);
        let cidr: defguard_wireguard_rs::net::IpAddrMask = "10.0.0.2/32".parse().unwrap();
        populated_peer.allowed_ips = vec![cidr];

        assert!(!PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![empty_peer],
            routes: vec![],
        }
        .has_any_peer());
        assert!(PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![populated_peer],
            routes: vec![],
        }
        .has_any_peer());
    }

    #[test]
    fn test_snapshot_latest_handshake_returns_max_or_none() {
        let now = SystemTime::now();

        // Empty snapshot.
        let snap_empty = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![],
            routes: vec![],
        };
        assert!(snap_empty.latest_handshake().is_none());

        // Snapshot with one peer that has a handshake 10s ago.
        let mut peer1 =
            defguard_wireguard_rs::peer::Peer::new(defguard_wireguard_rs::key::Key::new([1u8; 32]));
        peer1.last_handshake = Some(now - Duration::from_secs(10));
        let snap_one = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![peer1],
            routes: vec![],
        };
        let lh = snap_one.latest_handshake().unwrap();
        let elapsed = now.duration_since(lh).unwrap();
        assert!(elapsed >= Duration::from_secs(9) && elapsed <= Duration::from_secs(11));

        // Snapshot with two peers — latest is the most recent.
        let mut peer_a =
            defguard_wireguard_rs::peer::Peer::new(defguard_wireguard_rs::key::Key::new([2u8; 32]));
        peer_a.last_handshake = Some(now - Duration::from_secs(100));
        let mut peer_b =
            defguard_wireguard_rs::peer::Peer::new(defguard_wireguard_rs::key::Key::new([3u8; 32]));
        peer_b.last_handshake = Some(now - Duration::from_secs(5));
        let snap_two = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![peer_a, peer_b],
            routes: vec![],
        };
        let lh = snap_two.latest_handshake().unwrap();
        let elapsed = now.duration_since(lh).unwrap();
        assert!(elapsed >= Duration::from_secs(4) && elapsed <= Duration::from_secs(6));
    }

    #[test]
    fn test_snapshot_find_peer_returns_matching_or_none() {
        let pubkey_str = "HcxgCdgflJi7UZbhe2PZGx88ri6eFwyBnFv13VCxkXA=";
        let key: defguard_wireguard_rs::key::Key = pubkey_str.try_into().expect("valid pubkey");
        let snapshot = PollSnapshot {
            iface_name: "wg0".to_string(),
            peers: vec![defguard_wireguard_rs::peer::Peer::new(key)],
            routes: vec![],
        };
        assert!(snapshot.find_peer(pubkey_str).is_some());
        assert!(snapshot.find_peer("AAAA").is_none());
    }

    // --- sync_vpn_connection edge-case tests ---

    /// Peer present with allowed IPs AND handshake → connected.
    #[test]
    fn test_sync_connected_when_peer_present_and_handshake_received() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.vpn_connection = VpnConnectionState::Disconnected;
        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let now = SystemTime::now();
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        let cidr: defguard_wireguard_rs::net::IpAddrMask = "10.0.0.2/32".parse().unwrap();
        peer.allowed_ips = vec![cidr];
        peer.last_handshake = Some(now - Duration::from_secs(5));
        let snapshot = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![peer],
            routes: vec![],
        };
        sync_vpn_connection(&mut state, &snapshot);
        match state.vpn_connection {
            VpnConnectionState::Connected { .. } => {}
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    /// Peer present but with no handshake → disconnected.
    #[test]
    fn test_sync_disconnected_when_peer_present_but_no_handshake() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.vpn_connection = VpnConnectionState::Disconnected;
        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        let cidr: defguard_wireguard_rs::net::IpAddrMask = "10.0.0.2/32".parse().unwrap();
        peer.allowed_ips = vec![cidr];
        // No handshake set.
        let snapshot = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![peer],
            routes: vec![],
        };
        sync_vpn_connection(&mut state, &snapshot);
        assert!(
            matches!(state.vpn_connection, VpnConnectionState::Disconnected),
            "peer with no handshake should stay disconnected"
        );
    }

    /// Peer with handshake but empty allowed_ips does not count as present.
    #[test]
    fn test_sync_disconnected_when_peer_has_no_allowed_ips() {
        let mut state = make_state("alice", "10.0.0.2/32", ALICE_ID);
        state.vpn_connection = VpnConnectionState::Disconnected;
        let key = defguard_wireguard_rs::key::Key::new([1u8; 32]);
        let now = SystemTime::now();
        let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
        peer.last_handshake = Some(now - Duration::from_secs(5));
        // Intentionally empty allowed_ips.
        let snapshot = PollSnapshot {
            iface_name: "wg0".into(),
            peers: vec![peer],
            routes: vec![],
        };
        sync_vpn_connection(&mut state, &snapshot);
        assert!(
            matches!(state.vpn_connection, VpnConnectionState::Disconnected),
            "peer without allowed IPs should not trigger connectivity"
        );
    }
}
