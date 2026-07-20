use super::resolution;
use crate::state::SystemState;
use crate::telegram::TelegramClient;
use html_escape::encode_text;

/// Escape HTML in user-supplied strings before embedding them in Telegram responses.
/// Escapes &, <, > per WHATWG spec for text node context.
pub fn escape_html(input: &str) -> String {
    encode_text(input).to_string()
}

pub(crate) async fn send_html(
    client: &TelegramClient,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    client
        .send_message(chat_id, text, Some("HTML"))
        .await
        .map_err(|e| format!("Failed to send message: {}", e))
}

pub(crate) const UNKNOWN_COMMAND_MSG: &str = "Unknown command. Use /help for available commands.";

/// Build a peer-not-found error with the user's available peers listed.
/// Both `err` and `tail` are escaped to prevent HTML injection.
pub(crate) fn peer_not_found_msg(
    err: &str,
    state: &SystemState,
    user_id: i64,
    tail: &str,
) -> String {
    let peers = resolution::list_peer_names(&resolution::find_user_peers(state, user_id));
    format!(
        "❌ {}\nAvailable peers: {}{}",
        escape_html(err),
        peers,
        escape_html(tail)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_command_msg_is_non_empty() {
        assert!(!UNKNOWN_COMMAND_MSG.is_empty());
        assert!(UNKNOWN_COMMAND_MSG.contains("/help"));
    }

    /// Regression: angle brackets and ampersands in error messages are escaped.
    #[test]
    fn test_peer_not_found_msg_escapes_angle_brackets_and_ampersands() {
        let err = r#"Peer <bob> & not found"#;
        let state = crate::state::SystemState::from_config(crate::config::VpnConfig::default());
        let msg = peer_not_found_msg(err, &state, 42, "");
        // htmlize::escape_text escapes & < > but not quotes (text node context)
        assert!(msg.contains("&lt;"));
        assert!(msg.contains("&gt;"));
        assert!(msg.contains("&amp;"));
        assert!(msg.contains("Available peers:"));
    }

    /// Regression: script tags in tail strings must be escaped.
    #[test]
    fn test_peer_not_found_msg_escapes_script_in_tail() {
        let state = crate::state::SystemState::from_config(crate::config::VpnConfig::default());
        let msg = peer_not_found_msg("error", &state, 42, "\n<script>alert('xss')</script>");
        assert!(msg.contains("&lt;script&gt;"));
        assert!(!msg.contains("<script>"));
    }

    /// Regression: escape_html handles all relevant special characters per WHATWG spec.
    #[test]
    fn test_escape_html_handles_special_chars() {
        assert_eq!(escape_html("<b>"), "&lt;b&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("a > b"), "a &gt; b");
        assert_eq!(escape_html("normal"), "normal");
    }
}
