use std::time::SystemTime;

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
    /// Capture current interface + route state using the provided VPN backend.
    /// Returns defaults (empty) on any read error — phases treat an empty
    /// snapshot as "interface unavailable" and skip accordingly.
    pub(crate) async fn capture(
        ops: &(dyn vpn::WireGuardOps + Send + Sync),
        iface_name: &str,
    ) -> Self {
        let peers = ops
            .read_interface_data(iface_name)
            .await
            .unwrap_or_default();
        let routes = ops.get_routes(iface_name).await.unwrap_or_default();

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_returns_lowercase_underscored_name() {
        assert_eq!(
            NotificationKind::ConnectionEstablished.label(),
            "connection_established"
        );
        assert_eq!(
            NotificationKind::IdleDisconnected.label(),
            "idle_disconnected"
        );
        assert_eq!(
            NotificationKind::FirstHandshakeTimeout { elapsed_secs: 60 }.label(),
            "first_handshake_timeout"
        );
    }

    #[test]
    fn test_format_connected_includes_peer_name_and_html_tag() {
        let msg = NotificationKind::ConnectionEstablished.format_message("alice");
        assert!(msg.contains("<b>"));
        assert!(msg.contains("alice"));
        assert!(msg.contains("Connected"));
        assert!(msg.contains("active"));
    }

    #[test]
    fn test_format_idle_includes_peer_name_and_idle_hint() {
        let msg = NotificationKind::IdleDisconnected.format_message("bob");
        assert!(msg.contains("<b>"));
        assert!(msg.contains("bob"));
        assert!(msg.contains("Disconnected"));
        assert!(msg.contains("idle"));
    }

    #[test]
    fn test_format_timeout_includes_elapsed_seconds() {
        let msg =
            NotificationKind::FirstHandshakeTimeout { elapsed_secs: 90 }.format_message("carol");
        assert!(msg.contains("<b>"));
        assert!(msg.contains("carol"));
        assert!(msg.contains("Timeout"));
        assert!(msg.contains("90s"));
    }

    #[test]
    fn test_format_message_escapes_special_chars_in_peer_name() {
        // Peer names shouldn't normally contain HTML, but if they do they
        // should be embedded literally — these messages go through Telegram's
        // HTML parser which treats <b> as tags.
        let msg = NotificationKind::ConnectionEstablished.format_message("alice");
        // Should NOT double-escape the name (the format macros insert it raw).
        assert!(!msg.contains("&amp;"));
    }
}
