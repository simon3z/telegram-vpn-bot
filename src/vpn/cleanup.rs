//! Peer and route cleanup for startup crash recovery and shutdown.
//!
//! These functions touch every configured peer, so they live in their own
//! submodule rather than mixed with per-peer CRUD ops on the hot path.

use super::{delete_route, remove_wg_peer};
use defguard_wireguard_rs::{Kernel, WGApi, WireguardInterfaceApi};
use std::collections::HashSet;

use tracing::{info, warn};

/// Remove every peer and route belonging to this application from the
/// interface. Used at startup (crash recovery) and shutdown (clean exit).
///
/// Reads the current interface state once, then removes anything whose
/// public key or CIDR matches the configured peers. Errors are logged but do
/// not stop the process — partial cleanup is fine when the next cycle will
/// retry.
pub async fn cleanup_managed_peers(cfg: &crate::config::VpnConfig) -> Result<(), String> {
    let iface = &cfg.interface_name;

    // Snapshot the interface so we act on a consistent view.
    let peers: Vec<_> = WGApi::<Kernel>::new(iface)
        .and_then(|api| api.read_interface_data())
        .map(|d| d.peers.into_values().collect::<Vec<_>>())
        .map_err(|e| format!("failed to read {iface} during cleanup: {e}"))?;

    let keys: HashSet<String> = cfg.peers.iter().map(|p| p.public_key.clone()).collect();
    cleanup_wg_peers(iface, &peers, &keys);
    cleanup_routes(iface, cfg).await;

    info!("cleansed {iface} of managed peers and routes");

    Ok(())
}

/// Delete the host route for every configured peer.
async fn cleanup_routes(iface: &str, cfg: &crate::config::VpnConfig) {
    for peer in &cfg.peers {
        if let Err(e) = delete_route(iface, &peer.allowed_ips).await {
            warn!(
                "failed to delete route {} on {iface}: {e}",
                peer.allowed_ips
            );
        }
    }
}

/// Remove every configured peer that currently sits on the interface.
fn cleanup_wg_peers(
    iface: &str,
    peers: &[defguard_wireguard_rs::peer::Peer],
    configured_keys: &HashSet<String>,
) {
    for peer in peers {
        let pubkey = peer.public_key.to_string();
        if configured_keys.contains(&pubkey) {
            if let Err(e) = remove_wg_peer(iface, &pubkey) {
                warn!("failed to remove peer {pubkey} from {iface}: {e}");
            }
        }
    }
}
