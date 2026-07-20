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
                    &format!("Unknown command: {}. {}", other, send::UNKNOWN_COMMAND_MSG),
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
