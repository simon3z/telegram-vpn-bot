pub mod cleanup;
pub use cleanup::cleanup_managed_peers;

use std::time::SystemTime;

use async_trait::async_trait;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::{Kernel, WGApi, WireguardInterfaceApi};
use nlink::netlink::messages::RouteMessage;
use nlink::netlink::route::Ipv4Route;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over WireGuard peer management and Linux netlink route
/// operations. Implemented by [`KernelWgOps`] for real kernel interactions
/// and by mocks for testing.
///
/// All methods take the interface name explicitly — the trait does not hold
/// state about which interface it manages. This keeps implementations simple
/// and lets a single mock serve multiple interfaces during a test.
#[async_trait]
pub trait WireGuardOps: Send + Sync {
    /// Snapshot current peers from the interface.
    async fn read_interface_data(
        &self,
        iface: &str,
    ) -> Result<Vec<defguard_wireguard_rs::peer::Peer>, String>;

    /// Configure (add or update) a peer on the interface.
    async fn configure_peer(
        &self,
        iface: &str,
        peer: &defguard_wireguard_rs::peer::Peer,
    ) -> Result<(), String>;

    /// Remove a peer by public key from the interface.
    async fn remove_peer(&self, iface: &str, key: &Key) -> Result<(), String>;

    /// Query all routes on the interface.
    async fn get_routes(&self, iface: &str) -> Result<Vec<RouteMessage>, String>;

    /// Add an IP route to the interface.
    async fn add_route(&self, iface: &str, route: Ipv4Route) -> Result<(), String>;

    /// Delete an IP route from the interface.
    async fn delete_route(&self, iface: &str, route: Ipv4Route) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Kernel implementation
// ---------------------------------------------------------------------------

/// Real WireGuard + netlink backend. Delegates to lib-wg and nlink.
#[derive(Debug)]
pub(crate) struct KernelWgOps;

#[async_trait]
impl WireGuardOps for KernelWgOps {
    async fn read_interface_data(
        &self,
        iface: &str,
    ) -> Result<Vec<defguard_wireguard_rs::peer::Peer>, String> {
        let api =
            WGApi::<Kernel>::new(iface).map_err(|e| format!("failed to open {iface}: {e}"))?;
        let host = api
            .read_interface_data()
            .map_err(|e| format!("failed to read {iface}: {e}"))?;
        Ok(host.peers.into_values().collect())
    }

    async fn configure_peer(
        &self,
        iface: &str,
        peer: &defguard_wireguard_rs::peer::Peer,
    ) -> Result<(), String> {
        let api =
            WGApi::<Kernel>::new(iface).map_err(|e| format!("failed to open {iface}: {e}"))?;
        api.configure_peer(peer)
            .map_err(|e| format!("failed to configure peer on {iface}: {e}"))
    }

    async fn remove_peer(&self, iface: &str, key: &Key) -> Result<(), String> {
        let api =
            WGApi::<Kernel>::new(iface).map_err(|e| format!("failed to open {iface}: {e}"))?;
        api.remove_peer(key)
            .map_err(|e| format!("failed to remove peer from {iface}: {e}"))
    }

    async fn get_routes(&self, iface: &str) -> Result<Vec<RouteMessage>, String> {
        let conn = nlink::netlink::Connection::<nlink::netlink::Route>::new()
            .map_err(|e| format!("failed to create nlink connection: {e}"))?;
        conn.get_routes()
            .await
            .map_err(|e| format!("failed to query routes on {iface}: {e}"))
    }

    async fn add_route(&self, iface: &str, route: Ipv4Route) -> Result<(), String> {
        let conn = nlink::netlink::Connection::<nlink::netlink::Route>::new()
            .map_err(|e| format!("failed to create nlink connection: {e}"))?;
        conn.add_route(route)
            .await
            .map_err(|e| format!("failed to add route on {iface}: {e}"))
    }

    async fn delete_route(&self, iface: &str, route: Ipv4Route) -> Result<(), String> {
        let conn = nlink::netlink::Connection::<nlink::netlink::Route>::new()
            .map_err(|e| format!("failed to create nlink connection: {e}"))?;
        conn.del_route(route)
            .await
            .map_err(|e| format!("failed to delete route on {iface}: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Helper predicates
// ---------------------------------------------------------------------------

fn is_target_absent(error_text: &str) -> bool {
    error_text.contains("not found")
        || error_text.contains("No such device")
        || error_text.contains("No such file")
}

fn is_target_already_present(error_text: &str) -> bool {
    error_text.contains("already") || error_text.contains("exists")
}

// ---------------------------------------------------------------------------
// Public VPN helpers (still available to other modules)
// ---------------------------------------------------------------------------

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

/// Metadata about a WireGuard peer returned by [`get_peer_status`].
///
/// `endpoint` and `last_handshake` come straight from the kernel. Together
/// they tell us whether a real handshake happened:
///
/// - An endpoint requires a UDP packet from the client, which in turn requires
///   a completed handshake. Without one, any `last_handshake` reported by
///   lib-wg is the zero-sentinel wrapped into `UNIX_EPOCH`.
/// - We therefore only compute elapsed seconds when **both** fields are
///   populated; otherwise the peer has never shaken hands.
#[derive(Debug, Clone)]
pub enum PeerInfo {
    Inactive,
    Active {
        last_handshake: Option<SystemTime>,
        endpoint: Option<std::net::SocketAddr>,
    },
}

impl PeerInfo {
    /// Elapsed seconds since the most recent handshake, or `None` if none has
    /// occurred. Returns `None` unless both `last_handshake` and `endpoint`
    /// are populated — a peer cannot complete a cryptographic handshake
    /// without first establishing a UDP connection, so a missing endpoint
    /// invalidates any `last_handshake` value the kernel reports.
    pub fn seconds_since_last_handshake(&self) -> Option<u64> {
        let t = match self {
            Self::Active {
                last_handshake: Some(t),
                endpoint: Some(_),
            } => *t,
            _ => return None,
        };
        SystemTime::now()
            .duration_since(t)
            .ok()
            .map(|d| d.as_secs())
    }
}

/// Get the active state and metadata of a peer on the interface.
///
/// Uses the real kernel directly — intended for command-handler status checks
/// where constructing a trait object would be overhead.
pub fn get_peer_status(iface: &str, allowed_ips: &str) -> Result<(bool, PeerInfo), String> {
    let api = WGApi::<Kernel>::new(iface).map_err(|e| format!("failed to open {iface}: {e}"))?;
    let host = api
        .read_interface_data()
        .map_err(|e| format!("failed to read {iface}: {e}"))?;
    let target_cidr = allowed_ips.to_string();
    for peer in host.peers.values() {
        for allowed in &peer.allowed_ips {
            if allowed.to_string() == target_cidr {
                return Ok((
                    true,
                    PeerInfo::Active {
                        last_handshake: peer.last_handshake,
                        endpoint: peer.endpoint,
                    },
                ));
            }
        }
    }
    Ok((false, PeerInfo::Inactive))
}

/// Parse a CIDR string into an IP address and prefix length.
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

const ROUTE_PROTOCOL: nlink::netlink::types::route::RouteProtocol =
    nlink::netlink::types::route::RouteProtocol::Static;

/// Build an Ipv4Route deletion request using exact parameters reported by the
/// kernel. The kernel matches RTM_DELROUTE on the full discriminating key
/// (dst, prefix, oif, protocol, scope, priority, gateway), so passing back the
/// exact values the kernel reported guarantees the request targets the right
/// entry.
pub(crate) fn build_route_delete_request(
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

/// Ensure a WireGuard peer is configured on `iface`. Safe to call when the
/// peer is already configured — "already exists" errors are treated as success.
pub async fn ensure_wg_peer(
    ops: &(dyn WireGuardOps + Send + Sync),
    iface: &str,
    public_key: &str,
    peer_name: &str,
    cidr: &str,
) -> Result<(), String> {
    let key: Key = public_key
        .try_into()
        .map_err(|e| format!("Invalid public key format: {e}"))?;
    let cidr_mask: defguard_wireguard_rs::net::IpAddrMask = cidr
        .parse()
        .map_err(|e| format!("Invalid CIDR '{cidr}': {e}"))?;
    let mut peer = defguard_wireguard_rs::peer::Peer::new(key);
    peer.allowed_ips = vec![cidr_mask];
    match ops.configure_peer(iface, &peer).await {
        Ok(()) => {
            info!("added peer {public_key} to {iface}");
            Ok(())
        }
        Err(e) if is_target_already_present(&e) => {
            debug!("peer already configured on {iface}: {e}: peer={peer_name}, cidr={cidr}",);
            Ok(())
        }
        Err(e) => Err(format!("failed to configure peer on {iface}: {e}")),
    }
}

/// Add an IP route for `cidr` on `iface`. Safe to call when the route already
/// exists — "already exists" errors are treated as success.
pub async fn ensure_route(
    ops: &(dyn WireGuardOps + Send + Sync),
    iface: &str,
    cidr: &str,
) -> Result<(), String> {
    let (ip, prefix_len) = parse_cidr(cidr)?;
    let route_config = Ipv4Route::new(format!("{ip}"), prefix_len)
        .dev(iface)
        .protocol(ROUTE_PROTOCOL)
        .metric(50);
    match ops.add_route(iface, route_config).await {
        Ok(()) => {
            info!("added route {cidr} on {iface}");
            Ok(())
        }
        Err(e) if is_target_already_present(&e) => {
            debug!("route {cidr} already exists on {iface}: {e}");
            Ok(())
        }
        Err(e) => Err(format!("failed to add route {cidr} on {iface}: {e}")),
    }
}

/// Remove a WireGuard peer from the interface. Returns Ok(()) if the peer was
/// either removed successfully OR wasn't present to begin with.
pub async fn remove_wg_peer(
    ops: &(dyn WireGuardOps + Send + Sync),
    iface: &str,
    pubkey: &str,
) -> Result<(), String> {
    let key: Key = pubkey
        .try_into()
        .map_err(|e| format!("Invalid public key format: {e}"))?;
    match ops.remove_peer(iface, &key).await {
        Ok(()) => {
            info!("removed peer {pubkey} from {iface}");
            Ok(())
        }
        Err(e) if is_target_absent(&e) => {
            debug!("peer {pubkey} not on interface '{iface}' (already gone): {e}");
            Ok(())
        }
        Err(e) => Err(format!("failed to remove peer {pubkey} from {iface}: {e}")),
    }
}

/// Delete an IP route for the given CIDR on the interface. Skips deletion
/// if the route does not exist.
pub async fn delete_route(
    ops: &(dyn WireGuardOps + Send + Sync),
    iface: &str,
    cidr: &str,
) -> Result<(), String> {
    let (ip, prefix_len) = parse_cidr(cidr)?;
    let routes = match ops.get_routes(iface).await {
        Ok(r) => r,
        Err(e) => {
            debug!("could not read routes for {iface}: {e}");
            return Ok(());
        }
    };
    let matched = find_matching_route(&routes, ip, prefix_len);
    let route_msg = match matched {
        Some(r) => r,
        None => {
            debug!("route {cidr} not on {iface} (already gone)");
            return Ok(());
        }
    };
    let builder = build_route_delete_request(route_msg, iface, &ip, prefix_len);
    match ops.delete_route(iface, builder).await {
        Ok(()) => {
            info!("deleted route {cidr} on {iface}");
            Ok(())
        }
        Err(e) if e.contains("ESRCH") || e.contains("no such process") => {
            debug!("route {cidr} vanished between check and delete: {e}");
            Ok(())
        }
        Err(e) => Err(format!("failed to delete route {cidr} on {iface}: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    #[test]
    fn test_find_matching_route_finds_by_dst_and_prefix() {
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4("10.0.0.2".parse().unwrap()), 32)
            .build();
        let other_route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4("10.0.0.3".parse().unwrap()), 32)
            .build();
        let routes: Vec<_> = vec![route.clone(), other_route];
        let found = find_matching_route(&routes, "10.0.0.2".parse().unwrap(), 32);
        assert_eq!(found.unwrap().destination(), route.destination());
    }

    #[test]
    fn test_find_matching_route_ignores_wrong_prefix() {
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4("10.0.0.2".parse().unwrap()), 32)
            .build();
        // Requesting /24 should NOT match a /32 route.
        assert!(find_matching_route(&[route], "10.0.0.2".parse().unwrap(), 24).is_none());
    }

    #[test]
    fn test_find_matching_route_ignores_ipv6_routes() {
        let v6_route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv6()
            .destination(std::net::IpAddr::V6("fe80::1".parse().unwrap()), 64)
            .build();
        assert!(find_matching_route(&[v6_route], "10.0.0.2".parse().unwrap(), 32).is_none());
    }

    #[test]
    fn test_find_matching_route_returns_none_when_no_match() {
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4("10.0.0.2".parse().unwrap()), 32)
            .build();
        assert!(find_matching_route(&[route], "192.168.1.1".parse().unwrap(), 24).is_none());
    }

    #[test]
    fn test_build_route_delete_request_produces_valid_builder() {
        let route = nlink::netlink::messages::RouteMessageBuilder::new()
            .ipv4()
            .destination(std::net::IpAddr::V4("10.0.0.2".parse().unwrap()), 32)
            .build();
        // Just verify it produces a builder without panicking — Ipv4Route fields
        // are private but the builder must be constructable from any valid route msg.
        let _builder = build_route_delete_request(
            &route,
            "wg0",
            &"10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap(),
            32,
        );
    }

    #[test]
    fn test_is_target_absent_matches_common_error_strings() {
        assert!(is_target_absent("peer not found"));
        assert!(is_target_absent("No such device"));
        assert!(is_target_absent("No such file or directory"));
        assert!(!is_target_absent("permission denied"));
    }

    #[test]
    fn test_is_target_already_present_matches_common_error_strings() {
        assert!(is_target_already_present("already exists"));
        assert!(is_target_already_present("peer already configured"));
        assert!(!is_target_already_present("peer not found"));
    }
}

// ---------------------------------------------------------------------------
#[cfg(test)]
pub use self::mock::TrackedMock;

#[cfg(test)]
mod mock {
    use super::*;
    use async_trait::async_trait;

    /// In-memory mock implementing [`WireGuardOps`] for testing.
    ///
    /// Records every call and returns pre-configured responses. Fields are public so
    /// test code can inspect state directly; methods provide query shortcuts.
    #[derive(Debug)]
    pub struct MockWgOps {
        /// WireGuard peers reported by `read_interface_data`.
        pub peers: Vec<defguard_wireguard_rs::peer::Peer>,
        /// Routes reported by `get_routes`.
        pub routes: Vec<nlink::netlink::messages::RouteMessage>,
        write_error: Option<String>,
        read_error: Option<String>,
        /// Ordered call log — CRUD operations only (read ops are not tracked).
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl MockWgOps {
        /// Create a mock returning empty peer/route snapshots and succeeding writes.
        pub fn new() -> Self {
            Self {
                peers: vec![],
                routes: vec![],
                write_error: None,
                read_error: None,
                calls: std::sync::Mutex::new(vec![]),
            }
        }

        /// Make all write operations fail with the given reason.
        pub fn with_write_error(mut self, reason: impl Into<String>) -> Self {
            self.write_error = Some(reason.into());
            self
        }

        /// Make read operations (`read_interface_data`, `get_routes`) fail.
        pub fn with_read_error(mut self, reason: impl Into<String>) -> Self {
            self.read_error = Some(reason.into());
            self
        }

        // --- Push helpers for test setup ---

        /// Pre-load a route into the mock snapshot.
        pub fn push_route(&mut self, route: nlink::netlink::messages::RouteMessage) {
            self.routes.push(route);
        }

        /// Pre-load a peer into the mock snapshot.
        pub fn push_peer(&mut self, peer: defguard_wireguard_rs::peer::Peer) {
            self.peers.push(peer);
        }

        // --- Call counters / queries ---

        /// Has `configure_peer` been called?
        pub fn called_configure_peer(&self) -> bool {
            self.calls.lock().unwrap().iter().any(|c| c.as_str() == "configure_peer")
        }
        pub fn configure_peer_count(&self) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| **c == "configure_peer").count()
        }

        /// Has `remove_peer` been called?
        pub fn called_remove_peer(&self) -> bool {
            self.calls.lock().unwrap().iter().any(|c| c.as_str() == "remove_peer")
        }
        pub fn remove_peer_count(&self) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| **c == "remove_peer").count()
        }

        /// Has `add_route` been called?
        pub fn called_add_route(&self) -> bool {
            self.calls.lock().unwrap().iter().any(|c| c.as_str() == "add_route")
        }
        pub fn add_route_count(&self) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| **c == "add_route").count()
        }

        /// Has `delete_route` been called?
        pub fn called_delete_route(&self) -> bool {
            self.calls.lock().unwrap().iter().any(|c| c.as_str() == "delete_route")
        }
        pub fn delete_route_count(&self) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| **c == "delete_route").count()
        }

        /// Has `get_routes` been called? (Deprecated — the mock no longer tracks reads.)
        pub fn get_routes_count(&self) -> usize {
            0
        }

        /// Return a copy of the call history in execution order.
        pub fn call_history(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Default for MockWgOps {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl WireGuardOps for MockWgOps {
        async fn read_interface_data(
            &self,
            _iface: &str,
        ) -> Result<Vec<defguard_wireguard_rs::peer::Peer>, String> {
            if let Some(ref err) = self.read_error {
                return Err(err.clone());
            }
            Ok(self.peers.clone())
        }

        async fn configure_peer(
            &self,
            _iface: &str,
            _peer: &defguard_wireguard_rs::peer::Peer,
        ) -> Result<(), String> {
            self.calls.lock().unwrap().push("configure_peer".to_string());
            if let Some(e) = self.write_error.clone() {
                return Err(e);
            }
            Ok(())
        }

        async fn remove_peer(&self, _iface: &str, _key: &Key) -> Result<(), String> {
            self.calls.lock().unwrap().push("remove_peer".to_string());
            if let Some(e) = self.write_error.clone() {
                return Err(e);
            }
            Ok(())
        }

        /// Reads routes without recording the call (mirrors original behavior).
        async fn get_routes(&self, _iface: &str) -> Result<Vec<RouteMessage>, String> {
            if let Some(ref err) = self.read_error {
                return Err(err.clone());
            }
            Ok(self.routes.clone())
        }

        async fn add_route(&self, _iface: &str, _route: Ipv4Route) -> Result<(), String> {
            self.calls.lock().unwrap().push("add_route".to_string());
            if let Some(e) = self.write_error.clone() {
                return Err(e);
            }
            Ok(())
        }

        async fn delete_route(&self, _iface: &str, _route: Ipv4Route) -> Result<(), String> {
            self.calls.lock().unwrap().push("delete_route".to_string());
            if let Some(e) = self.write_error.clone() {
                return Err(e);
            }
            Ok(())
        }
    }

    /// Backwards-compatible alias — existing test code can still use
    /// `crate::vpn::TrackedMock`.
    pub use MockWgOps as TrackedMock;
}

