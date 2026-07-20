use std::time::SystemTime;

use defguard_wireguard_rs::WireguardInterfaceApi;

use crate::vpn;

/// Wake-up signal from command handlers. Carries no payload — the receiver
/// side simply triggers an immediate loop iteration.
pub(crate) type WakeSignal = ();

/// Snapshot of WireGuard interface state captured once per poll cycle.
/// Holds peer data and route table so all phases can query presence without
/// re-dumping the kernel.
#[derive(Clone)]
pub(crate) struct PollSnapshot {
    pub(crate) iface_name: String,
    pub(crate) peers: Vec<defguard_wireguard_rs::peer::Peer>,
    pub(crate) routes: Vec<nlink::netlink::messages::RouteMessage>,
}

impl PollSnapshot {
    /// Capture current interface + route state. Returns defaults (empty)
    /// on any read error — phases treat an empty snapshot as "interface
    /// unavailable" and skip accordingly.
    pub(crate) async fn capture(iface_name: &str) -> Self {
        let peers = defguard_wireguard_rs::WGApi::<defguard_wireguard_rs::Kernel>::new(iface_name)
            .and_then(|api| api.read_interface_data())
            .map(|d| d.peers.into_values().collect())
            .unwrap_or_default();

        let routes = match nlink::netlink::Connection::<nlink::netlink::Route>::new() {
            Ok(conn) => conn.get_routes().await.unwrap_or_else(|_| vec![]),
            Err(_) => vec![],
        };

        Self {
            iface_name: iface_name.to_string(),
            peers,
            routes,
        }
    }

    pub(crate) fn iface_name(&self) -> &str {
        &self.iface_name
    }

    /// Whether the given public key is currently configured on the interface.
    pub(crate) fn peer_on_iface(&self, pubkey: &str) -> bool {
        self.peers
            .iter()
            .any(|p| p.public_key.to_string() == pubkey)
    }

    /// Whether a route for the given CIDR appears in the dumped table.
    pub(crate) fn route_for_cidr(&self, cidr: &str) -> bool {
        let (ip, prefix_len) = match vpn::parse_cidr(cidr) {
            Ok(v) => v,
            Err(_) => return false,
        };
        vpn::find_matching_route(&self.routes, ip, prefix_len).is_some()
    }

    /// Whether any peer with non-empty allowed IPs is on the interface.
    pub(crate) fn has_any_peer(&self) -> bool {
        self.peers.iter().any(|p| !p.allowed_ips.is_empty())
    }

    /// Latest handshake timestamp across all peers, if any.
    pub(crate) fn latest_handshake(&self) -> Option<SystemTime> {
        self.peers.iter().filter_map(|p| p.last_handshake).max()
    }

    /// Find a peer by public key string.
    pub(crate) fn find_peer(&self, pubkey: &str) -> Option<&defguard_wireguard_rs::peer::Peer> {
        self.peers
            .iter()
            .find(|p| p.public_key.to_string() == pubkey)
    }
}

/// Kinds of peer-state changes that warrant a Telegram notification.
#[derive(Debug, PartialEq)]
pub enum NotificationKind {
    /// Peer completed its first successful handshake.
    ConnectionEstablished,
    /// Session went idle past the timeout threshold.
    IdleDisconnected,
    /// First handshake did not arrive within the configured window.
    FirstHandshakeTimeout { elapsed_secs: u64 },
}

impl NotificationKind {
    /// Human-readable label for structured logging.
    pub fn label(&self) -> &'static str {
        match self {
            NotificationKind::ConnectionEstablished => "connection_established",
            NotificationKind::IdleDisconnected => "idle_disconnected",
            NotificationKind::FirstHandshakeTimeout { .. } => "first_handshake_timeout",
        }
    }

    /// Format a user-facing message for this notification kind.
    pub fn format_message(&self, peer_name: &str) -> String {
        match self {
            NotificationKind::ConnectionEstablished => Self::format_connected(peer_name),
            NotificationKind::IdleDisconnected => Self::format_idle(peer_name),
            NotificationKind::FirstHandshakeTimeout { elapsed_secs } => {
                Self::format_timeout(peer_name, *elapsed_secs)
            }
        }
    }

    fn format_connected(peer_name: &str) -> String {
        format!("<b>✅ Peer '{peer_name}' Connected</b>\n\nYour peer is now active.")
    }

    fn format_idle(peer_name: &str) -> String {
        format!("<b>❌ Peer '{peer_name}' Disconnected</b>\n\nSession went idle.")
    }

    fn format_timeout(peer_name: &str, elapsed_secs: u64) -> String {
        format!(
            "<b>❌ Peer '{peer_name}' Timeout</b>\n\n\
             Could not establish connection within {elapsed_secs}s.",
        )
    }
}

/// Notification sent to a user when a state change occurs.
#[derive(Debug)]
pub struct NotificationEvent {
    pub user_id: i64,
    pub peer_name: String,
    pub kind: NotificationKind,
}

/// The monitoring loop task handle. Aborts cleanly on drop.
pub struct MonitorHandle {
    pub(crate) handle: tokio::task::JoinHandle<()>,
}

impl MonitorHandle {
    /// Abort the monitoring loop. Consumes the handle; subsequent calls panic.
    pub fn abort(self) {
        self.handle.abort();
    }
}
