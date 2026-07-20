pub mod health;
pub mod phases;
pub mod reconcile;
pub mod timeouts;
pub mod types;

pub use types::NotificationEvent;

pub(crate) use phases::spawn_monitor;

#[cfg(test)]
mod tests {
    use super::reconcile::reconcile_all;
    use super::types::PollSnapshot;
    use crate::state::DesiredState;
    use crate::test_fixtures::*;
    use std::time::{Duration, SystemTime};

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
        let original_first_seen = SystemTime::now() - Duration::from_secs(100);
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
}
