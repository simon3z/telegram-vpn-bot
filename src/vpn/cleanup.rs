//! Peer and route cleanup for startup crash recovery and shutdown.
//!
//! These functions touch every configured peer, so they live in their own
//! submodule rather than mixed with per-peer CRUD ops on the hot path.

use super::{delete_route, remove_wg_peer, WireGuardOps};
use std::collections::HashSet;

use tracing::{info, warn};

/// Remove every peer and route belonging to this application from the
/// interface. Used at startup (crash recovery) and shutdown (clean exit).
///
/// Reads the current interface state once, then removes anything whose
/// public key or CIDR matches the configured peers. Errors are logged but do
/// not stop the process — partial cleanup is fine when the next cycle will
/// retry.
pub async fn cleanup_managed_peers(
    ops: &(dyn WireGuardOps + Send + Sync),
    cfg: &crate::config::VpnConfig,
) -> Result<(), String> {
    let iface = &cfg.interface_name;

    // Snapshot the interface so we act on a consistent view.
    let peers = match ops.read_interface_data(iface).await {
        Ok(p) => p,
        Err(e) => return Err(format!("failed to read {iface} during cleanup: {e}")),
    };

    let keys: HashSet<String> = cfg.peers.iter().map(|p| p.public_key.clone()).collect();
    cleanup_wg_peers(ops, iface, &peers, &keys).await;
    cleanup_routes(ops, iface, cfg).await;

    info!("cleansed {iface} of managed peers and routes");

    Ok(())
}

/// Delete the host route for every configured peer.
async fn cleanup_routes(
    ops: &(dyn WireGuardOps + Send + Sync),
    iface: &str,
    cfg: &crate::config::VpnConfig,
) {
    for peer in &cfg.peers {
        if let Err(e) = delete_route(ops, iface, &peer.allowed_ips).await {
            warn!(
                "failed to delete route {} on {iface}: {e}",
                peer.allowed_ips
            );
        }
    }
}

/// Remove every configured peer that currently sits on the interface.
async fn cleanup_wg_peers(
    ops: &(dyn WireGuardOps + Send + Sync),
    iface: &str,
    peers: &[defguard_wireguard_rs::peer::Peer],
    configured_keys: &HashSet<String>,
) {
    for peer in peers {
        let pubkey = peer.public_key.to_string();
        if configured_keys.contains(&pubkey) {
            if let Err(e) = remove_wg_peer(ops, iface, &pubkey).await {
                warn!("failed to remove peer {pubkey} from {iface}: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;
    use crate::vpn::TrackedMock;

    /// Helper: build a valid 32-byte WireGuard public key string.
    fn wg_pubkey(bytes: [u8; 32]) -> String {
        use defguard_wireguard_rs::key::Key;
        Key::new(bytes).to_string()
    }

    /// Only peers whose public key matches a configured entry are removed.
    /// Unconfigured peers on the interface are left alone.
    #[tokio::test]
    async fn test_cleanup_removes_configured_only() {
        let mock = TrackedMock::new();
        let alice_pubkey = wg_pubkey([1u8; 32]);

        let cfg = crate::config::VpnConfig {
            interface_name: "wg0".to_string(),
            peers: vec![PeerConfig {
                telegram_id: 111,
                name: "alice".to_string(),
                allowed_ips: "10.0.0.2/32".to_string(),
                public_key: alice_pubkey.clone(),
            }],
            ..Default::default()
        };

        // Pre-populate the mock with both a configured and unconfigured peer.
        mock.push_peer(defguard_wireguard_rs::peer::Peer::new(
            defguard_wireguard_rs::key::Key::new([1u8; 32]),
        ));
        mock.push_peer(defguard_wireguard_rs::peer::Peer::new(
            defguard_wireguard_rs::key::Key::new([2u8; 32]),
        ));

        cleanup_managed_peers(&mock, &cfg).await.ok();

        // configure_peer should NOT have been called.
        assert_eq!(mock.configure_peer_count(), 0);

        // remove_peer should have been called exactly once (for alice only).
        assert_eq!(mock.remove_peer_count(), 1);
        // add_route/delete_route should not have been called by cleanup_wg_peers.
        assert_eq!(mock.add_route_count(), 0);

        // get_routes should not have been called (cleanup reads peers, not routes).
        assert_eq!(mock.get_routes_count(), 0);
    }

    /// Every configured peer's route is deleted regardless of whether the
    /// peer itself was present on the interface.
    #[tokio::test]
    async fn test_cleanup_deletes_routes_for_all_configured_peers() {
        let mock = TrackedMock::new();
        // Pre-populate mock routes so delete_route finds them and calls through.
        for cidr in &["10.0.0.2/32", "10.0.0.3/32"] {
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip: std::net::Ipv4Addr = parts[0].parse().unwrap();
            let prefix: u8 = parts[1].parse().unwrap();
            let route = nlink::netlink::messages::RouteMessageBuilder::new()
                .ipv4()
                .destination(std::net::IpAddr::V4(ip), prefix)
                .build();
            mock.push_route(route);
        }

        let cfg = crate::config::VpnConfig {
            interface_name: "wg0".to_string(),
            peers: vec![
                PeerConfig {
                    telegram_id: 111,
                    name: "alice".to_string(),
                    allowed_ips: "10.0.0.2/32".to_string(),
                    public_key: wg_pubkey([1u8; 32]),
                },
                PeerConfig {
                    telegram_id: 222,
                    name: "bob".to_string(),
                    allowed_ips: "10.0.0.3/32".to_string(),
                    public_key: wg_pubkey([2u8; 32]),
                },
            ],
            ..Default::default()
        };

        cleanup_managed_peers(&mock, &cfg).await.ok();

        // Both peers' routes should be deleted.
        assert_eq!(mock.delete_route_count(), 2);
    }

    /// Cleanup returns an error when the interface cannot be read.
    #[tokio::test]
    async fn test_cleanup_returns_error_on_read_failure() {
        let mock = TrackedMock::with_read_error("simulated read failure");
        let cfg = crate::config::VpnConfig {
            interface_name: "wg0".to_string(),
            peers: vec![PeerConfig {
                telegram_id: 111,
                name: "alice".to_string(),
                allowed_ips: "10.0.0.2/32".to_string(),
                public_key: wg_pubkey([1u8; 32]),
            }],
            ..Default::default()
        };

        let result = cleanup_managed_peers(&mock, &cfg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read wg0"));
    }

    /// Individual peer removal failures do not stop the rest of cleanup.
    /// Routes are still cleaned up even when a peer could not be removed.
    #[tokio::test]
    async fn test_cleanup_continues_after_individual_failures() {
        let mock = TrackedMock::with_write_error("simulated write failure");
        // Pre-populate mock with the configured peer AND a matching route.
        mock.push_peer(defguard_wireguard_rs::peer::Peer::new(
            defguard_wireguard_rs::key::Key::new([1u8; 32]),
        ));
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                32,
            )
            .build();
        mock.push_route(route);

        let cfg = crate::config::VpnConfig {
            interface_name: "wg0".to_string(),
            peers: vec![PeerConfig {
                telegram_id: 111,
                name: "alice".to_string(),
                allowed_ips: "10.0.0.2/32".to_string(),
                public_key: wg_pubkey([1u8; 32]),
            }],
            ..Default::default()
        };

        // Cleanup should succeed overall — individual failures are logged,
        // not propagated.
        let result = cleanup_managed_peers(&mock, &cfg).await;
        assert!(
            result.is_ok(),
            "cleanup should tolerate individual failures"
        );

        // Both remove_peer and delete_route were attempted despite failing.
        assert_eq!(mock.remove_peer_count(), 1);
        assert_eq!(mock.delete_route_count(), 1);
    }
}
