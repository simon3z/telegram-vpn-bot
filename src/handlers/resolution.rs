use crate::state::SystemState;

/// Maximum length for incoming Telegram message text.
const MAX_MESSAGE_LEN: usize = 4096;

/// Maximum length for a single command argument (peer name, etc.).
const MAX_ARG_LEN: usize = 64;

/// Validate that `text` looks like a command rather than arbitrary input.
/// Rejects empty/single-char strings, non-command messages, and inputs
/// exceeding configured size limits.
fn is_valid_command_input(text: &str) -> bool {
    if text.len() == 1 || text.len() > MAX_MESSAGE_LEN {
        return false;
    }
    text.starts_with('/')
}

/// Parse a text message into (command, args). Returns None for non-command
/// messages or malformed/too-long input.
///
/// Sanitizes arguments to prevent excessively long strings from causing
/// memory issues or slow string operations.
pub(crate) fn parse_command(text: &str) -> Option<(String, Vec<String>)> {
    let text = text.trim_start();
    if !is_valid_command_input(text) {
        return None;
    }
    let rest = &text[1..];
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let cmd = parts.first().filter(|s| !s.is_empty())?;
    let args: Vec<String> = parts[1..]
        .iter()
        .take_while(|s| !s.is_empty())
        .map(|s| {
            let trimmed = s.trim_end();
            if trimmed.len() > MAX_ARG_LEN {
                trimmed[..MAX_ARG_LEN].to_string()
            } else {
                trimmed.to_string()
            }
        })
        .collect();
    Some((format!("/{}", cmd), args))
}

/// Find all VPN peers belonging to a user.
pub(crate) fn find_user_peers(state: &SystemState, user_id: i64) -> Vec<&crate::state::PeerState> {
    state
        .peers
        .iter()
        .filter(|p| p.config.telegram_id == user_id)
        .collect()
}

/// Format a single peer's row as HTML.
pub(crate) fn format_single_peer(peer: &crate::state::PeerState, iface: &str) -> String {
    match crate::vpn::get_peer_status(iface, &peer.config.allowed_ips) {
        Ok(Some(info)) => {
            let hs_line = match info.seconds_since_last_handshake() {
                Some(secs) => format!("   Last handshake: {secs}s ago"),
                None => "   Last handshake: never".to_string(),
            };
            format!(
                "✅ <b>{}</b>\n   CIDR: <code>{}</code>\n   Status: active\n{}",
                peer.config.name, peer.config.allowed_ips, hs_line
            )
        }
        Ok(None) => format!(
            "⏸️ <b>{}</b>\n   CIDR: <code>{}</code>\n   Status: inactive",
            peer.config.name, peer.config.allowed_ips
        ),
        Err(e) => format!("❌ {} — error: {}", peer.config.name, e),
    }
}

/// Format a peer list as HTML for display.
pub(crate) fn format_peer_list(peers: &[&crate::state::PeerState], iface: &str) -> String {
    let lines: Vec<String> = peers.iter().map(|p| format_single_peer(p, iface)).collect();
    format!(
        "📋 <b>Your VPN Peers</b>\n\n{}\n\nInterface: <code>{}</code>",
        lines.join("\n\n"),
        iface
    )
}

/// Join peer names with backticks for display in error messages.
pub(crate) fn list_peer_names(peers: &[&crate::state::PeerState]) -> String {
    if peers.is_empty() {
        "none".to_string()
    } else {
        peers
            .iter()
            .map(|p| format!("`{}`", p.config.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SystemState;
    use crate::test_fixtures::*;

    #[test]
    fn test_parse_command_simple() {
        assert_eq!(
            parse_command("/enable alice"),
            Some(("/enable".to_string(), vec!["alice".to_string()])),
        );
    }

    #[test]
    fn test_parse_command_no_args() {
        assert_eq!(parse_command("/help"), Some(("/help".to_string(), vec![])));
    }

    #[test]
    fn test_parse_command_non_command_returns_none() {
        assert_eq!(parse_command("hello world"), None);
    }

    #[test]
    fn test_parse_command_empty_after_slash_returns_none() {
        assert_eq!(parse_command("/"), None);
    }

    #[test]
    fn test_parse_command_truncates_long_args() {
        let long_arg = "a".repeat(100);
        let result = parse_command(&format!("/enable {}", long_arg)).unwrap();
        assert_eq!(result.1[0].len(), 64);
    }

    #[test]
    fn test_parse_command_rejects_overlong_messages() {
        let long_msg = "/enable ".to_string() + &"a".repeat(5000);
        assert_eq!(parse_command(&long_msg), None);
    }

    #[test]
    fn test_parse_command_normal_length_still_works() {
        let result = parse_command("/enable alice").unwrap();
        assert_eq!(result.0, "/enable");
        assert_eq!(result.1, vec!["alice"]);
    }

    #[test]
    fn test_parse_command_strips_leading_whitespace() {
        let result = parse_command("   /enable alice").unwrap();
        assert_eq!(result.0, "/enable");
        assert_eq!(result.1, vec!["alice"]);
    }

    #[test]
    fn test_parse_command_handles_multiple_args() {
        let result = parse_command("/enable alice bob carol").unwrap();
        assert_eq!(result.0, "/enable");
        assert_eq!(result.1, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn test_parse_command_trims_trailing_whitespace_on_args() {
        let result = parse_command("/enable alice   ").unwrap();
        assert_eq!(result.1, vec!["alice"]);
    }

    #[test]
    fn test_parse_command_rejects_single_character_input() {
        assert_eq!(parse_command("a"), None);
    }

    #[test]
    fn test_parse_command_preserves_truncated_content_up_to_limit() {
        let long_arg = "abcdefghij";
        let result = parse_command(&format!("/enable {}", long_arg)).unwrap();
        assert_eq!(result.1[0], long_arg);
    }

    #[test]
    fn test_resolve_peer_finds_by_name() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let peer = st.resolve_peer(TEST_USER_ID, Some("alice")).unwrap();
        assert_eq!(peer.config.name, "alice");
        assert_eq!(peer.config.allowed_ips, "10.0.0.2/32");
    }

    #[test]
    fn test_resolve_peer_unknown_name() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let err = st.resolve_peer(TEST_USER_ID, Some("bob")).unwrap_err();
        assert!(err.contains("not found"));
        assert!(err.contains("bob"));
    }

    #[test]
    fn test_resolve_peer_scoped_by_user_id() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let err = st.resolve_peer(999, Some("alice")).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_resolve_peer_no_name_picks_single_peer() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let peer = st.resolve_peer(TEST_USER_ID, None).unwrap();
        assert_eq!(peer.config.name, "alice");
    }

    #[test]
    fn test_resolve_peer_no_name_fails_when_empty() {
        let st = SystemState::from_config(crate::config::VpnConfig {
            interface_name: "wg0".into(),
            peers: vec![],
            ..Default::default()
        });
        let err = st.resolve_peer(TEST_USER_ID, None).unwrap_err();
        assert!(err.contains("No VPN peers"));
    }

    #[test]
    fn test_find_user_peers_filters_by_id() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let peers = find_user_peers(&st, TEST_USER_ID);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].config.name, "alice");
    }

    #[test]
    fn test_find_user_peers_empty_for_unknown_user() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let peers = find_user_peers(&st, 999);
        assert!(peers.is_empty());
    }

    #[test]
    fn test_list_peer_names_joins_with_backticks() {
        let st = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let peers: Vec<&crate::state::PeerState> = find_user_peers(&st, TEST_USER_ID);
        let names = list_peer_names(&peers);
        assert_eq!(names, "`alice`");
    }

    #[test]
    fn test_list_peer_names_empty_returns_none() {
        assert_eq!(list_peer_names(&[]), "none");
    }

    // --- Cross-user isolation ---

    #[test]
    fn test_resolve_peer_refuses_other_users_peer_by_name() {
        let st = make_multi_state();
        let peer = st.resolve_peer(ALICE_ID, Some("laptop")).unwrap();
        assert_eq!(peer.config.telegram_id, ALICE_ID);
        assert_eq!(peer.config.allowed_ips, "10.0.0.2/32");
    }

    #[test]
    fn test_resolve_peer_cannot_access_others_peer_even_with_matching_name() {
        let st = make_multi_state();
        let peer = st.resolve_peer(BOB_ID, Some("laptop")).unwrap();
        assert_eq!(peer.config.telegram_id, BOB_ID);
        assert_eq!(peer.config.allowed_ips, "10.0.0.4/32");
    }

    #[test]
    fn test_find_user_peers_doesnt_leak_other_users() {
        let st = make_multi_state();
        let alice_peers = find_user_peers(&st, ALICE_ID);
        let bob_peers = find_user_peers(&st, BOB_ID);

        assert_eq!(alice_peers.len(), 2);
        assert_eq!(bob_peers.len(), 2);

        for a in &alice_peers {
            for b in &bob_peers {
                assert_ne!(a.config.telegram_id, b.config.telegram_id);
            }
        }
    }

    #[test]
    fn test_resolve_peer_unknown_name_from_wrong_user_still_missing() {
        let st = make_multi_state();
        let err = st.resolve_peer(ALICE_ID, Some("tablet")).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_resolve_peer_returns_peer_with_correct_telegram_id() {
        let st = make_multi_state();

        let p1 = st.resolve_peer(ALICE_ID, Some("laptop")).unwrap();
        let p2 = st.resolve_peer(BOB_ID, Some("laptop")).unwrap();

        assert_eq!(p1.config.telegram_id, ALICE_ID);
        assert_eq!(p2.config.telegram_id, BOB_ID);
        assert_ne!(p1.config.public_key, p2.config.public_key);
        assert_ne!(p1.config.allowed_ips, p2.config.allowed_ips);
    }

    /// Regression: an enabled-but-not-connected peer must show "Last handshake:
    /// never". lib-wg wraps the kernel's zero-sentinel into `UNIX_EPOCH`, so a
    /// peer with `last_handshake = UNIX_EPOCH` and no endpoint has never
    /// completed a handshake despite being configured on the interface.
    #[test]
    fn test_peer_status_epoch_handshake_and_no_endpoint_shows_never() {
        use std::time::SystemTime;

        use crate::vpn::PeerStatus;

        let info = PeerStatus {
            last_handshake: Some(SystemTime::UNIX_EPOCH),
            endpoint: None,
        };

        assert!(
            info.seconds_since_last_handshake().is_none(),
            "expected 'never' for an enabled-but-not-connected peer, \
             but got {:?}",
            info.seconds_since_last_handshake(),
        );
    }

    /// A peer with a real handshake timestamp AND a known endpoint must report
    /// elapsed seconds — confirms the endpoint guard does not over-match.
    #[test]
    fn test_peer_status_real_handshake_and_endpoint_reports_elapsed() {
        use std::time::{Duration, SystemTime};

        use crate::vpn::PeerStatus;

        let five_seconds_ago = SystemTime::now() - Duration::from_secs(5);
        let info = PeerStatus {
            last_handshake: Some(five_seconds_ago),
            endpoint: Some("1.2.3.4:51820".parse().unwrap()),
        };

        let secs = info.seconds_since_last_handshake();
        assert!(secs.is_some(), "expected elapsed seconds, got None");
        let secs = secs.unwrap();
        assert!(
            (5..=7).contains(&secs),
            "expected ~5 seconds elapsed, got {secs}"
        );
    }
}
