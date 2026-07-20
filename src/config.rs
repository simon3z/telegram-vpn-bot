use serde::Deserialize;

/// Root configuration structure parsed from TOML.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub bot: BotConfig,
    #[serde(default)]
    pub polling: PollingConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
    #[serde(default)]
    pub vpn: VpnConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub users: Vec<UserEntry>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct BotConfig {
    pub token: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PollingConfig {
    pub timeout: u64,
    pub limit: u64,
}

/// A single whitelisted Telegram user.
#[derive(Debug, Clone, Deserialize)]
pub struct UserEntry {
    /// Telegram user ID.
    pub id: i64,
    /// Display name (informational only).
    pub name: Option<String>,
}

/// WireGuard interface configuration.
/// The sysadmin creates the interface separately; this section tells the bot
/// which peers exist and how to manage them.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct VpnConfig {
    /// Interface name (e.g. "wg0").
    pub interface_name: String,
    /// Peers mapped to Telegram users.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// How often the connection monitor polls the WireGuard interface (seconds).
    #[serde(default = "default_status_poll_interval")]
    pub status_poll_interval: u64,
    /// Seconds after enabling before a peer must complete its first handshake (otherwise auto-disable).
    #[serde(default = "default_first_handshake_timeout")]
    pub first_handshake_timeout: u64,
}

fn default_status_poll_interval() -> u64 {
    10
}
fn default_first_handshake_timeout() -> u64 {
    60
}

/// A single peer definition mapping a Telegram user to a WireGuard peer.
/// All peers start disabled; the daemon disables any that are left on the interface on startup.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Telegram user ID this peer belongs to.
    pub telegram_id: i64,
    /// Display name shown in /status.
    pub name: String,
    /// CIDR assigned to this peer (e.g. "10.8.0.2/32").
    pub allowed_ips: String,
    /// Pre-generated public key (base64). Required for proper peer management across restarts.
    pub public_key: String,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path, e))?;

        let cfg: Self = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse TOML config from '{}': {}", path, e))?;

        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate the configuration. Runs all field, uniqueness, and cross-peer
    /// checks; returns the first error encountered.
    fn validate(&self) -> Result<(), String> {
        self.validate_required_fields()?;
        self.validate_unique_cidrs()?;
        self.validate_unique_names_per_user()?;
        Ok(())
    }

    /// Each peer must have non-empty `allowed_ips` and `public_key`.
    fn validate_required_fields(&self) -> Result<(), String> {
        for peer in &self.vpn.peers {
            if peer.allowed_ips.is_empty() {
                return Err(format!("Peer '{}' has empty allowed_ips", peer.name));
            }
            if peer.public_key.is_empty() {
                return Err(format!("Peer '{}' has empty public_key", peer.name));
            }
        }
        Ok(())
    }

    /// Every peer must have a distinct `allowed_ips` value.
    fn validate_unique_cidrs(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for peer in &self.vpn.peers {
            if !seen.insert(peer.allowed_ips.clone()) {
                return Err(format!(
                    "Duplicate CIDR '{}' assigned to peer '{}', \
                     already used by another peer",
                    peer.allowed_ips, peer.name
                ));
            }
        }
        Ok(())
    }

    /// Each user may not have two peers sharing the same name.
    fn validate_unique_names_per_user(&self) -> Result<(), String> {
        let mut user_names: std::collections::HashMap<i64, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for peer in &self.vpn.peers {
            let set = user_names.entry(peer.telegram_id).or_default();
            if !set.insert(peer.name.clone()) {
                return Err(format!(
                    "User {} has multiple peers named '{}'",
                    peer.telegram_id, peer.name
                ));
            }
        }
        Ok(())
    }

    /// Get the bot token from config.
    pub fn get_token(&self) -> Result<String, String> {
        self.bot
            .token
            .as_ref()
            .filter(|t| !t.is_empty())
            .cloned()
            .ok_or_else(|| {
                "No bot token configured. Set 'token' in [bot] section of config.toml".to_string()
            })
    }

    /// Parse a config string directly (exposed for tests).
    #[cfg(test)]
    pub(crate) fn parse(toml_str: &str) -> Result<Self, String> {
        let cfg: Self =
            toml::from_str(toml_str).map_err(|e| format!("Failed to parse TOML config: {}", e))?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: missing token field produces a clear error.
    #[test]
    fn test_get_token_missing_field_error() {
        let cfg = Config {
            bot: crate::config::BotConfig { token: None },
            ..Default::default()
        };
        let err = cfg.get_token().unwrap_err();
        assert!(err.contains("No bot token"));
    }

    /// Regression: empty string token is treated as missing.
    #[test]
    fn test_get_token_empty_string_rejected() {
        let cfg = Config {
            bot: crate::config::BotConfig {
                token: Some(String::new()),
            },
            ..Default::default()
        };
        let err = cfg.get_token().unwrap_err();
        assert!(err.contains("No bot token"));
    }

    /// Regression: valid non-empty token is returned unchanged.
    #[test]
    fn test_get_token_valid_token_accepted() {
        let cfg = Config {
            bot: crate::config::BotConfig {
                token: Some("000000:AAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.get_token().unwrap(),
            "000000:AAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    /// Regression: parsing a minimal valid config produces defaults for optional fields.
    #[test]
    fn test_parse_minimal_config_uses_defaults() {
        let cfg = Config::parse(
            r#"
        [vpn]
        interface_name = "wg0"
        "#,
        )
        .unwrap();

        assert_eq!(cfg.vpn.interface_name, "wg0");
        assert_eq!(cfg.vpn.status_poll_interval, 10); // default
        assert_eq!(cfg.vpn.first_handshake_timeout, 60); // default
        assert!(cfg.vpn.peers.is_empty());
    }

    /// Regression: malformed TOML surfaces a readable error instead of panicking.
    #[test]
    fn test_parse_malformed_toml_returns_error() {
        let result = Config::parse("[vpn\ninterface_name wg0");
        assert!(result.is_err(), "expected parse error, got Ok");
        let err = result.unwrap_err();
        assert!(err.contains("Failed to parse TOML"), "error msg: {err}");
    }

    /// Regression: loading a nonexistent file reports the missing path clearly.
    #[test]
    fn test_load_nonexistent_file_reports_path() {
        let err = Config::load("/tmp/does_not_exist_telegram_vpn_bot_test_xyz.toml").unwrap_err();
        assert!(err.contains("does_not_exist_telegram_vpn_bot_test_xyz.toml"));
        assert!(err.contains("Failed to read"));
    }

    /// Regression: a minimal config with explicit poll interval and handshake
    /// timeout overrides the defaults.
    #[test]
    fn test_parse_overrides_defaults() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        status_poll_interval = 30
        first_handshake_timeout = 120
        "#;
        let cfg = Config::parse(input).unwrap();
        assert_eq!(cfg.vpn.status_poll_interval, 30);
        assert_eq!(cfg.vpn.first_handshake_timeout, 120);
    }

    /// Regression: poll interval default matches the documented 10-second cadence.
    #[test]
    fn test_default_status_poll_interval_is_ten_seconds() {
        let cfg = Config::parse("[vpn]\ninterface_name = \"wg0\"").unwrap();
        assert_eq!(cfg.vpn.status_poll_interval, 10);
    }

    /// Regression: handshake timeout default matches the documented 60-second window.
    #[test]
    fn test_default_first_handshake_timeout_is_sixty_seconds() {
        let cfg = Config::parse("[vpn]\ninterface_name = \"wg0\"").unwrap();
        assert_eq!(cfg.vpn.first_handshake_timeout, 60);
    }

    /// Validation rejects duplicate CIDRs across peers.
    #[test]
    fn test_validate_rejects_duplicate_cidrs() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        [[vpn.peers]]
        telegram_id = 111
        name = "peer_a"
        allowed_ips = "10.0.0.2/32"
        public_key = "AAAAAAAAliceAAA"
        [[vpn.peers]]
        telegram_id = 222
        name = "peer_b"
        allowed_ips = "10.0.0.2/32"
        public_key = "BBBBBBBbobBBB"
        "#;
        let err = Config::parse(input).unwrap_err();
        assert!(err.contains("Duplicate CIDR"));
        assert!(err.contains("10.0.0.2/32"));
    }

    /// Validation rejects duplicate peer names within a single user.
    #[test]
    fn test_validate_rejects_duplicate_names_per_user() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        [[vpn.peers]]
        telegram_id = 111
        name = "laptop"
        allowed_ips = "10.0.0.2/32"
        public_key = "AAAAAAAAliceAAA"
        [[vpn.peers]]
        telegram_id = 111
        name = "laptop"
        allowed_ips = "10.0.0.3/32"
        public_key = "BBBBBBBbobBBB"
        "#;
        let err = Config::parse(input).unwrap_err();
        assert!(err.contains("multiple peers named"));
        assert!(err.contains("laptop"));
    }

    /// Same peer name is allowed across different users.
    #[test]
    fn test_validate_allows_same_name_across_users() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        [[vpn.peers]]
        telegram_id = 111
        name = "laptop"
        allowed_ips = "10.0.0.2/32"
        public_key = "AAAAAAAAliceAAA"
        [[vpn.peers]]
        telegram_id = 222
        name = "laptop"
        allowed_ips = "10.0.0.3/32"
        public_key = "BBBBBBBbobBBB"
        "#;
        let cfg = Config::parse(input).unwrap();
        assert_eq!(cfg.vpn.peers.len(), 2);
    }

    /// Validation rejects peers with empty allowed_ips.
    #[test]
    fn test_validate_rejects_empty_allowed_ips() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        [[vpn.peers]]
        telegram_id = 111
        name = "bad_peer"
        allowed_ips = ""
        public_key = "AAAAAAAAliceAAA"
        "#;
        let err = Config::parse(input).unwrap_err();
        assert!(err.contains("empty allowed_ips"));
    }

    /// Validation rejects peers with empty public_key.
    #[test]
    fn test_validate_rejects_empty_public_key() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        [[vpn.peers]]
        telegram_id = 111
        name = "bad_peer"
        allowed_ips = "10.0.0.2/32"
        public_key = ""
        "#;
        let err = Config::parse(input).unwrap_err();
        assert!(err.contains("empty public_key"));
    }

    /// Valid minimal config passes validation.
    #[test]
    fn test_validate_accepts_valid_config() {
        let input = r#"
        [vpn]
        interface_name = "wg0"
        [[vpn.peers]]
        telegram_id = 111
        name = "laptop"
        allowed_ips = "10.0.0.2/32"
        public_key = "AAAAAAAAliceAAA="
        "#;
        let cfg = Config::parse(input).unwrap();
        assert_eq!(cfg.vpn.peers.len(), 1);
    }
}
