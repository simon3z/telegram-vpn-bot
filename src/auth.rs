use crate::config::Config;
use std::sync::RwLock;

use tracing::info;

/// Global whitelist of authorized Telegram user IDs.
///
/// Uses `RwLock` rather than `OnceLock` so tests can clear the state between
/// runs without panicking. Production code calls [`init_whitelist_from_config`]
/// exactly once at startup; the lock is write-locked for that single call and
/// read-locked on every request.
static WHITELIST: RwLock<Vec<i64>> = RwLock::new(Vec::new());

/// Initialize the global whitelist from config. Call once at startup.
///
/// Replaces any existing whitelist contents. Safe to call multiple times
/// (e.g., during config hot-reload or test teardown).
pub fn init_whitelist_from_config(cfg: &Config) {
    let entries: Vec<(i64, &str)> = cfg
        .whitelist
        .users
        .iter()
        .map(|u| {
            let name = u.name.as_deref().unwrap_or("<unnamed>");
            (u.id, name)
        })
        .collect();
    let ids: Vec<i64> = entries.iter().map(|&(id, _)| id).collect();
    *WHITELIST.write().expect("whitelist lock poisoned") = ids;
    info!("whitelist loaded: {} authorized users", entries.len());
    for &(id, name) in &entries {
        info!("  - {name} (ID: {id})");
    }
}

/// Check whether a user ID is whitelisted given a specific list.
pub fn is_whitelisted_list(user_id: Option<i64>, list: &[i64]) -> bool {
    match user_id {
        Some(id) => {
            let whitelisted = list.contains(&id);
            if !whitelisted {
                info!("unauthorized user attempted to access bot: {id}");
            }
            whitelisted
        }
        None => {
            info!("message without sender attempted to access bot");
            false
        }
    }
}

/// Check whether a user ID is whitelisted against the global list.
pub fn is_whitelisted(user_id: Option<i64>) -> bool {
    let list = WHITELIST.read().expect("whitelist lock poisoned");
    is_whitelisted_list(user_id, &list)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: an unauthenticated message (no sender) must always be denied,
    /// regardless of whether the whitelist has been populated.
    #[test]
    fn test_is_whitelisted_none_denied_regardless_of_whitelist_state() {
        assert!(!is_whitelisted_list(None, &[111_222_333])); // populated
        assert!(!is_whitelisted_list(None, &[])); // empty
    }

    /// Regression: after populating the whitelist, known IDs must be accepted
    /// and unknown IDs must be rejected.
    #[test]
    fn test_is_whitelisted_known_id_allowed_and_unknown_denied() {
        let list = vec![111_222_333, 444_555_666];

        assert!(is_whitelisted_list(Some(111_222_333), &list));
        assert!(is_whitelisted_list(Some(444_555_666), &list));
        assert!(!is_whitelisted_list(Some(0), &list));
        assert!(!is_whitelisted_list(Some(-1), &list));
        assert!(!is_whitelisted_list(Some(999_999_999), &list));
    }
}
