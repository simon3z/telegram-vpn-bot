//! Shared test fixtures used across modules.
//!
//! Declared behind `#[cfg(test)]` in `main.rs` so production builds never pay
//! for these symbols.

use crate::config::PeerConfig;
use crate::state::{PeerState, SystemState};

/// Canonical test user IDs. Chosen to be large enough to avoid collisions with
/// real Telegram IDs while remaining easy to spot in logs.
pub const ALICE_ID: i64 = 111_111_111;
pub const BOB_ID: i64 = 222_222_222;
pub const TEST_USER_ID: i64 = 42;

/// Canonical test public key shared across every fixture.
const TEST_PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Build a [`PeerConfig`] with canonical test values.
pub fn make_peer_cfg(name: &str, cidr: &str, id: i64) -> PeerConfig {
    PeerConfig {
        telegram_id: id,
        name: name.to_string(),
        allowed_ips: cidr.to_string(),
        public_key: TEST_PUBLIC_KEY.to_string(),
    }
}

/// Build a [`PeerState`] starting from scratch.
pub fn make_peer_state(name: &str, cidr: &str, id: i64) -> PeerState {
    PeerState::new(make_peer_cfg(name, cidr, id))
}

/// Build a [`SystemState`] containing a single peer.
pub fn make_state(peer_name: &str, cidr: &str, id: i64) -> SystemState {
    SystemState::from_config(crate::config::VpnConfig {
        interface_name: "wg0".into(),
        peers: vec![make_peer_cfg(peer_name, cidr, id)],
        ..Default::default()
    })
}

/// Build a multi-user system state for cross-user isolation tests.
///
/// Two users (Alice and Bob), each with two peers under different names so
/// name-collision resolution can be verified. Each peer gets a distinct
/// public key so cross-user equality checks remain meaningful.
pub fn make_multi_state() -> SystemState {
    SystemState::from_config(crate::config::VpnConfig {
        interface_name: "wg0".into(),
        peers: vec![
            crate::config::PeerConfig {
                telegram_id: ALICE_ID,
                name: "laptop".into(),
                allowed_ips: "10.0.0.2/32".into(),
                public_key: "AAAAAAAliceAAA".into(),
            },
            crate::config::PeerConfig {
                telegram_id: ALICE_ID,
                name: "phone".into(),
                allowed_ips: "10.0.0.3/32".into(),
                public_key: "BBBBBBBbobBBB".into(),
            },
            crate::config::PeerConfig {
                telegram_id: BOB_ID,
                name: "laptop".into(),
                allowed_ips: "10.0.0.4/32".into(),
                public_key: "CCCCCCCbobCCC".into(),
            },
            crate::config::PeerConfig {
                telegram_id: BOB_ID,
                name: "tablet".into(),
                allowed_ips: "10.0.0.5/32".into(),
                public_key: "DDDDDDDbobDDD".into(),
            },
        ],
        ..Default::default()
    })
}
