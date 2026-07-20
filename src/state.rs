use std::time::Duration;

use crate::config::PeerConfig;

/// Operator-declared intent for a managed peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DesiredState {
    #[default]
    Disabled,
    Enabled,
}

/// Per-peer runtime state maintained by the monitoring loop.
#[derive(Debug)]
pub struct PeerState {
    pub config: PeerConfig,
    pub desired: DesiredState,
    /// When the peer first appeared on the interface (for first-handshake timeout).
    pub first_seen_at: Option<std::time::SystemTime>,
    /// Timestamp of the most recent successful handshake from the kernel.
    /// `None` means no handshake has occurred yet.
    pub last_handshake: Option<std::time::SystemTime>,
}

impl PeerState {
    /// Initial state for a newly-loaded peer from config.
    pub fn new(config: PeerConfig) -> Self {
        Self {
            config,
            desired: DesiredState::Disabled,
            first_seen_at: None,
            last_handshake: None,
        }
    }
}

/// Global VPN tunnel connection state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum VpnConnectionState {
    #[default]
    Disconnected,
    Connected {
        last_handshake: std::time::SystemTime,
    },
}

/// The single source of truth for the entire system.
pub struct SystemState {
    pub peers: Vec<PeerState>,
    pub vpn_connection: VpnConnectionState,
    pub config: crate::config::VpnConfig,
}

impl SystemState {
    /// Build initial state from parsed configuration. All peers start disabled.
    pub fn from_config(cfg: crate::config::VpnConfig) -> Self {
        let peers = cfg.peers.iter().cloned().map(PeerState::new).collect();
        Self {
            peers,
            vpn_connection: VpnConnectionState::Disconnected,
            config: cfg,
        }
    }

    /// Resolve a peer by user and optional name. Returns the peer reference
    /// or an error describing why resolution failed.
    pub fn resolve_peer<'a>(
        &'a self,
        user_id: i64,
        peer_name: Option<&str>,
    ) -> Result<&'a PeerState, String> {
        match peer_name {
            Some(name) => self
                .peers
                .iter()
                .find(|p| p.config.telegram_id == user_id && p.config.name == name)
                .ok_or_else(|| format!("Peer \"{}\" not found", name)),
            None => self
                .peers
                .iter()
                .find(|p| p.config.telegram_id == user_id)
                .ok_or_else(|| "No VPN peers configured for you.".into()),
        }
    }

    /// Set the desired state for a peer (called by command handlers).
    pub fn set_desired_for_user(
        &mut self,
        user_id: i64,
        peer_name: &str,
        desired: DesiredState,
    ) -> bool {
        if let Some(peer) = self
            .peers
            .iter_mut()
            .find(|p| p.config.telegram_id == user_id && p.config.name == peer_name)
        {
            peer.desired = desired;
            true
        } else {
            false
        }
    }

    /// Get the interface name from config.
    pub fn interface_name(&self) -> &str {
        &self.config.interface_name
    }
}

// --- Helper constants ---

/// Seconds after which an idle connected VPN is considered dead. Matches
/// WireGuard's ~2 minute handshake renewal cycle.
pub const IDLE_TIMEOUT_SECS: u64 = 180;

/// Maximum elapsed time a freshly-enabled peer may take to complete its first
/// handshake before being auto-disabled.
pub fn first_handshake_timeout_secs(config: &crate::config::VpnConfig) -> Duration {
    Duration::from_secs(config.first_handshake_timeout)
}

/// Status poll interval from config.
pub fn poll_interval(config: &crate::config::VpnConfig) -> Duration {
    Duration::from_secs(config.status_poll_interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_cfg(name: &str, cidr: &str, id: i64) -> PeerConfig {
        PeerConfig {
            telegram_id: id,
            name: name.to_string(),
            allowed_ips: cidr.to_string(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        }
    }

    #[test]
    fn test_new_peer_starts_disabled_not_present() {
        let ps = PeerState::new(make_peer_cfg("alice", "10.0.0.2/32", 111));
        assert_eq!(ps.desired, DesiredState::Disabled);
        assert!(ps.first_seen_at.is_none());
        assert!(ps.last_handshake.is_none());
    }

    #[test]
    fn test_set_desired_updates_correct_peer() {
        let mut ss = SystemState::from_config(crate::config::VpnConfig {
            interface_name: "wg0".into(),
            peers: vec![make_peer_cfg("alice", "10.0.0.2/32", 111)],
            ..Default::default()
        });
        assert!(ss.set_desired_for_user(111, "alice", DesiredState::Enabled));
        let alice = ss.peers.iter().find(|p| p.config.name == "alice").unwrap();
        assert_eq!(alice.desired, DesiredState::Enabled);
        assert!(!ss.set_desired_for_user(999, "nonexistent", DesiredState::Enabled));
    }

    #[test]
    fn test_vpn_connection_state_default_is_disconnected() {
        let ss = SystemState::from_config(crate::config::VpnConfig::default());
        assert_eq!(ss.vpn_connection, VpnConnectionState::Disconnected);
    }

    #[test]
    fn test_first_handshake_timeout_reads_from_config() {
        let cfg = crate::config::VpnConfig {
            first_handshake_timeout: 120,
            ..Default::default()
        };
        assert_eq!(first_handshake_timeout_secs(&cfg), Duration::from_secs(120));
    }
}
