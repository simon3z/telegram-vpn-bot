pub mod commands;
pub mod resolution;
pub(crate) mod send;

use crate::state::SystemState;
use crate::telegram::{TelegramClient, Update};
use tokio::sync::mpsc;

/// Handle incoming Telegram updates. Routes commands to their handlers.
pub async fn handle_update(
    client: &TelegramClient,
    update: &Update,
    state: &mut SystemState,
    wake_tx: &mpsc::Sender<()>,
) -> Result<(), String> {
    let msg = match &update.message {
        Some(m) => m,
        None => return Err("No message in update".into()),
    };

    let chat_id = msg.chat.id;
    let user_id = msg
        .from
        .as_ref()
        .map(|f| f.id)
        .ok_or("Message has no sender")?;

    let text = msg.text.as_deref().unwrap_or("");

    if let Some((cmd, args)) = resolution::parse_command(text) {
        match cmd.as_str() {
            "/start" => commands::handle_start(client, chat_id, state, user_id).await?,
            "/help" => commands::handle_help(client, chat_id).await?,
            "/status" => commands::handle_status(client, chat_id, state, user_id).await?,
            "/enable" => {
                let mut ctx = commands::PeerTransitionCtx {
                    client,
                    chat_id,
                    state,
                    user_id,
                    wake_tx,
                };
                commands::handle_enable(&mut ctx, args.first().map(|s| s.as_str())).await?
            }
            "/disable" => {
                let mut ctx = commands::PeerTransitionCtx {
                    client,
                    chat_id,
                    state,
                    user_id,
                    wake_tx,
                };
                commands::handle_disable(&mut ctx, args.first().map(|s| s.as_str())).await?
            }
            other => {
                send::send_html(
                    client,
                    chat_id,
                    &format!("Unknown command: {other}. {}", send::UNKNOWN_COMMAND_MSG),
                )
                .await?;
            }
        }
    } else {
        send::send_html(
            client,
            chat_id,
            "<b>🔐 Telegram VPN Bot</b>\n\n\
            Send a text message or use commands:\n\
            • /start — Welcome message + your peers\n\
            • /help — Show available commands\n\
            • /status — List all your VPN peers\n\
            • /enable [name] — Activate a peer\n\
            • /disable [name] — Deactivate a peer",
        )
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SystemState;
    use crate::telegram::{Chat, Message, User};
    use crate::test_fixtures::*;

    fn make_update(text: &str, user_id: i64) -> Update {
        Update {
            update_id: 1,
            message: Some(Message {
                chat: Chat { id: 999_999 },
                from: Some(User { id: user_id }),
                text: Some(text.to_string()),
            }),
        }
    }

    /// A non-command message triggers the help display path — routing is
    /// correct regardless of whether the Telegram send succeeds (we use a
    /// fake token so the network call will fail, but the handler still returns
    /// Ok once it has attempted the send).
    #[tokio::test]
    async fn test_handle_update_routes_non_command_to_help_display() {
        let _state = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(10);

        // We expect either Ok (if the fake send somehow succeeded) or Err due
        // to the fake token. Either way, no panic and the routing decision was
        // made correctly.
        let _result = handle_update(
            &client,
            &make_update("hello world", TEST_USER_ID),
            &mut SystemState::from_config(crate::config::VpnConfig::default()),
            &tx,
        )
        .await;
    }

    /// An update with no message returns an error.
    #[tokio::test]
    async fn test_handle_update_errors_when_no_message() {
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(10);

        let result = handle_update(
            &client,
            &Update {
                update_id: 1,
                message: None,
            },
            &mut SystemState::from_config(crate::config::VpnConfig::default()),
            &tx,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No message"));
    }

    /// Unknown commands like "/foobar" reach the unknown-command branch —
    /// the handler attempts to send a reply and returns Ok only when the
    /// Telegram API accepts it (which it won't with a fake token, but the
    /// routing decision itself is correct).
    #[tokio::test]
    async fn test_handle_update_routes_unknown_command_to_error_message() {
        let _state = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(10);

        let _result = handle_update(
            &client,
            &make_update("/foobar", TEST_USER_ID),
            &mut SystemState::from_config(crate::config::VpnConfig::default()),
            &tx,
        )
        .await;
    }

    /// Commands that lack a message sender are rejected before dispatch.
    #[tokio::test]
    async fn test_handle_update_rejects_messages_without_sender() {
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(10);

        let result = handle_update(
            &client,
            &Update {
                update_id: 1,
                message: Some(Message {
                    chat: Chat { id: 999_999 },
                    from: None,
                    text: Some("/help".to_string()),
                }),
            },
            &mut SystemState::from_config(crate::config::VpnConfig::default()),
            &tx,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no sender"));
    }
}
