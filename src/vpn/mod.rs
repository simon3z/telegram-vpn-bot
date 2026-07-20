pub mod cleanup;
pub use cleanup::cleanup_managed_peers;

use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::{Kernel, WGApi, WireguardInterfaceApi};
use nlink::netlink::messages::RouteMessage;
use nlink::netlink::route::Ipv4Route;
use nlink::netlink::{Connection, Route};
use std::time::SystemTime;

use tracing::{debug, info};

/// Predicate: does this error text indicate the target resource does not exist?
/// Covers WireGuard "not found" / "No such device" errors and related netlink
/// failure messages. Used to silence expected-absence paths in idempotent ops.
fn is_target_absent(error_text: &str) -> bool {
    error_text.contains("not found")
        || error_text.contains("No such device")
        || error_text.contains("No such file")
}

/// Predicate: does this error text indicate the target resource already exists?
/// Covers WireGuard "already exists" / lib-wg duplicate-key errors.
fn is_target_already_present(error_text: &str) -> bool {
    error_text.contains("already") || error_text.contains("exists")
}

/// Look up a route in a dumped table by destination IPv4 address and prefix
/// length. The kernel's fib-lookup cannot distinguish our peer-specific route
/// from unrelated routes to the same IP, so we walk the full table client-side.
pub fn find_matching_route(
    routes: &[RouteMessage],
    ip: std::net::Ipv4Addr,
    prefix_len: u8,
) -> Option<&RouteMessage> {
    routes.iter().find(|r| {
        r.is_ipv4()
            && r.dst_len() == prefix_len
            && r.destination().and_then(|a| match a {
                std::net::IpAddr::V4(v4) => Some(*v4),
                _ => None,
            }) == Some(ip)
    })
}

/// Get the active state and metadata of a peer in a single interface read.
pub fn get_peer_status(iface: &str, allowed_ips: &str) -> Result<(bool, PeerInfo), String> {
    let api = wgapi_for(iface)?;
    match load_interface_peer(&api, allowed_ips)? {
        Some(info) => Ok((true, info)),
        None => Ok((false, PeerInfo::Inactive)),
    }
}

/// Metadata about a WireGuard peer returned by `get_peer_status`.
#[derive(Debug, Clone)]
pub enum PeerInfo {
    /// Peer is inactive or absent from the interface.
    Inactive,
    /// Peer is present on the interface with its last handshake timestamp.
    Active {
        last_handshake: Option<std::time::SystemTime>,
    },
}

impl PeerInfo {
    /// Seconds since the last successful handshake, or `None` if none recorded.
    pub fn seconds_since_last_handshake(&self) -> Option<u64> {
        match self {
            Self::Inactive => None,
            Self::Active {
                last_handshake: Some(t),
                ..
            } => SystemTime::now()
                .duration_since(*t)
                .ok()
                .map(|d| d.as_secs()),
            Self::Active {
                last_handshake: None,
                ..
            } => None,
        }
    }
}

/// Look up a peer on the interface by its allowed-IPs CIDR.
pub fn load_interface_peer(
    api: &WGApi<Kernel>,
    allowed_ips: &str,
) -> Result<Option<PeerInfo>, String> {
    let target_cidr = allowed_ips.to_string();

    for peer in api
        .read_interface_data()
        .map_err(|e| format!("Failed to read interface data: {e}"))?
        .peers
        .values()
    {
        for allowed in &peer.allowed_ips {
            if allowed.to_string() == target_cidr {
                return Ok(Some(PeerInfo::Active {
                    last_handshake: peer.last_handshake,
                }));
            }
        }
    }

    Ok(None)
}

/// Build a WGApi handle for the given interface.
fn wgapi_for(iface: &str) -> Result<WGApi<Kernel>, String> {
    WGApi::new(iface).map_err(|e| format!("failed to create WGApi for '{iface}': {e}"))
}

/// Parse a CIDR string into an IP address and prefix length.
///
/// Validates that:
/// - The string has exactly one '/' separator
/// - The left side is a valid IPv4 address
/// - The right side is a number in 0..=32 (valid IPv4 prefix range)
pub fn parse_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR format: {cidr}"));
    }

    let ip: std::net::Ipv4Addr = parts[0]
        .parse()
        .map_err(|e| format!("invalid IP address: {e}"))?;
    let prefix_str = parts[1];
    let prefix_len: u8 = prefix_str
        .parse()
        .map_err(|e| format!("invalid prefix length '{prefix_str}': {e}"))?;
    if prefix_len > 32 {
        return Err(format!(
            "invalid prefix length {prefix_str} for IPv4 (must be 0..=32)"
        ));
    }

    Ok((ip, prefix_len))
}

/// Remove a WireGuard peer from the interface. Returns Ok(()) if the peer was
/// either removed successfully OR wasn't present to begin with.
pub(crate) fn remove_wg_peer(iface: &str, pubkey: &str) -> Result<(), String> {
    let api = wgapi_for(iface)?;

    let key: Key = pubkey
        .try_into()
        .map_err(|e| format!("Invalid public key format: {e}"))?;

    match api.remove_peer(&key) {
        Ok(()) => {
            info!("removed peer {pubkey} from {iface}");
            Ok(())
        }
        Err(e) if is_target_absent(&e.to_string()) => {
            debug!("peer {pubkey} not on interface '{iface}' (already gone): {e}");
            Ok(())
        }
        Err(e) => Err(format!("failed to remove peer {pubkey} from {iface}: {e}")),
    }
}

/// Delete an IP route for the given CIDR on the interface. Skips deletion
/// if the route does not exist.
pub(crate) async fn delete_route(iface: &str, cidr: &str) -> Result<(), String> {
    let conn = Connection::<Route>::new()
        .map_err(|e| format!("failed to create nlink connection: {e}"))?;

    let (ip, prefix_len) = parse_cidr(cidr)?;

    // Walk the kernel route table and match on destination IP + prefix length.
    let routes = conn
        .get_routes()
        .await
        .map_err(|e| format!("failed to query routes on {iface}: {e}"))?;
    let matched = find_matching_route(&routes, ip, prefix_len);

    let route_msg = match matched {
        Some(r) => r,
        None => {
            debug!("route {cidr} not on {iface} (already gone)");
            return Ok(());
        }
    };

    let builder = build_route_delete_request(route_msg, iface, &ip, prefix_len);

    match conn.del_route(builder).await {
        Ok(()) => {
            info!("deleted route {cidr} on {iface}");
            Ok(())
        }
        Err(e) if e.errno() == Some(libc::ESRCH) => {
            debug!("route {cidr} vanished between check and delete: {e}");
            Ok(())
        }
        Err(e) => Err(format!("failed to delete route {cidr} on {iface}: {e}")),
    }
}

/// Build an Ipv4Route deletion request using exact parameters reported by the
/// kernel. The kernel matches RTM_DELROUTE on the full discriminating key
/// (dst, prefix, oif, protocol, scope, priority, gateway), so passing back the
/// exact values the kernel reported guarantees the request targets the right
/// entry.
fn build_route_delete_request(
    route_msg: &RouteMessage,
    iface: &str,
    ip: &std::net::Ipv4Addr,
    prefix_len: u8,
) -> Ipv4Route {
    let mut builder = Ipv4Route::new(format!("{ip}"), prefix_len);

    if let Some(oif) = route_msg.oif() {
        builder = builder.dev_index(oif);
    } else {
        builder = builder.dev(iface);
    }

    builder = builder
        .protocol(route_msg.protocol())
        .scope(route_msg.scope());

    if let Some(priority) = route_msg.priority() {
        builder = builder.priority(priority);
    }

    if let Some(std::net::IpAddr::V4(v4)) = route_msg.gateway() {
        builder = builder.gateway(*v4);
    }

    builder
}

/// Configure the WireGuard peer on `iface` for the given public key and CIDR.
/// Safe to call when the peer is already configured — "already exists" errors
/// are treated as success.
pub fn ensure_wg_peer(
    iface: &str,
    public_key: &str,
    peer_name: &str,
    cidr: &str,
) -> Result<(), String> {
    let api = wgapi_for(iface)?;

    let key: Key = public_key
        .try_into()
        .map_err(|e| format!("Invalid public key format: {e}"))?;

    let cidr_mask: defguard_wireguard_rs::net::IpAddrMask = cidr
        .parse()
        .map_err(|e| format!("Invalid CIDR '{cidr}': {e}"))?;

    let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
    peer.allowed_ips = vec![cidr_mask];

    match api.configure_peer(&peer) {
        Ok(()) => {
            info!("added peer {public_key} to {iface}");
            Ok(())
        }
        Err(e) if is_target_already_present(&e.to_string()) => {
            debug!("peer already configured on {iface}: {e}: peer={peer_name}, cidr={cidr}",);
            Ok(())
        }
        Err(e) => Err(format!("failed to configure peer on {iface}: {e}")),
    }
}

const ROUTE_PROTOCOL: nlink::netlink::types::route::RouteProtocol =
    nlink::netlink::types::route::RouteProtocol::Static;

/// Add an IP route for `cidr` on `iface`. Safe to call when the route already
/// exists — "already exists" errors are treated as success.
pub async fn ensure_route(iface: &str, cidr: &str) -> Result<(), String> {
    let conn = Connection::<Route>::new()
        .map_err(|e| format!("failed to create nlink connection: {e}"))?;

    let (ip, prefix_len) = parse_cidr(cidr)?;

    let route_config = Ipv4Route::new(format!("{ip}"), prefix_len)
        .dev(iface)
        .protocol(ROUTE_PROTOCOL)
        .metric(50);

    match conn.add_route(route_config).await {
        Ok(()) => {
            info!("added route {cidr} on {iface}");
            Ok(())
        }
        Err(e) if is_target_already_present(&e.to_string()) => {
            debug!("route {cidr} already exists on {iface}: {e}");
            Ok(())
        }
        Err(e) => Err(format!("failed to add route {cidr} on {iface}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_valid_ipv4() {
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip.to_string(), "192.168.1.0");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_host_route() {
        let (ip, prefix) = parse_cidr("10.0.0.5/32").unwrap();
        assert_eq!(ip.to_string(), "10.0.0.5");
        assert_eq!(prefix, 32);
    }

    #[test]
    fn test_parse_cidr_default_route() {
        let (ip, prefix) = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(ip.to_string(), "0.0.0.0");
        assert_eq!(prefix, 0);
    }

    #[test]
    fn test_parse_cidr_invalid_format_missing_slash() {
        let err = parse_cidr("192.168.1.0").unwrap_err();
        assert!(err.contains("invalid CIDR format"));
    }

    #[test]
    fn test_parse_cidr_invalid_format_two_slashes() {
        let err = parse_cidr("192.168.1.0/24/8").unwrap_err();
        assert!(err.contains("invalid CIDR format"));
    }

    #[test]
    fn test_parse_cidr_invalid_ip() {
        let err = parse_cidr("not.an.ip/24").unwrap_err();
        assert!(err.contains("invalid IP address"));
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_length() {
        let err = parse_cidr("192.168.1.0/33").unwrap_err();
        assert!(err.contains("invalid prefix length"));
    }

    #[test]
    fn test_parse_cidr_empty_string() {
        let err = parse_cidr("").unwrap_err();
        assert!(err.contains("invalid CIDR format"));
    }
}
