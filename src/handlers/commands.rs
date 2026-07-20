use super::resolution;
use super::send;
use crate::state::{DesiredState, SystemState};
use crate::telegram::TelegramClient;
use tokio::sync::mpsc;

/// Returns the list of available commands, formatted as HTML.
pub(crate) fn command_list() -> &'static str {
    "<b>Available Commands:</b>\n\n\
    📋 <code>/status</code> — View your VPN peers and their status\n\
    ✅ <code>/enable [name]</code> — Knock to activate a peer\n\
    ❌ <code>/disable [name]</code> — Remove a peer from the interface\n\
    ❓ <code>/help</code> — Show this help message\n\
    👋 <code>/start</code> — Welcome message + your peers\n\n\
    <b>How It Works:</b>\n\
    This bot implements port knocking over WireGuard. Your peers stay invisible \
    until you explicitly activate them with /enable. Once idle for 3 minutes or \
    if no initial handshake completes within 60 seconds, the peer is auto-disabled."
}

pub(crate) async fn handle_start(
    client: &TelegramClient,
    chat_id: i64,
    state: &SystemState,
    user_id: i64,
) -> Result<(), String> {
    let peers = resolution::find_user_peers(state, user_id);
    let iface = state.interface_name();

    if peers.is_empty() {
        let _ = send::send_html(
            client,
            chat_id,
            "👋 <b>Welcome to Telegram VPN Bot!</b>\n\n\
            You are whitelisted but have no VPN peers configured yet.",
        )
        .await;
        return Ok(());
    }

    let peer_details = resolution::format_peer_list(&peers, iface);
    send::send_html(
        client,
        chat_id,
        &format!(
            "👋 <b>Welcome to Telegram VPN Bot!</b>\n\n\
            I manage your WireGuard peers on the pre-configured VPN server.\n\n\
            {}\n\n\
            {}",
            peer_details,
            command_list(),
        ),
    )
    .await?;

    Ok(())
}

pub(crate) async fn handle_help(client: &TelegramClient, chat_id: i64) -> Result<(), String> {
    send::send_html(client, chat_id, command_list()).await
}

pub(crate) async fn handle_status(
    client: &TelegramClient,
    chat_id: i64,
    state: &SystemState,
    user_id: i64,
) -> Result<(), String> {
    let peers = resolution::find_user_peers(state, user_id);
    if peers.is_empty() {
        let _ = send::send_html(
            client,
            chat_id,
            "ℹ️ You are whitelisted but no VPN peers are configured for you yet.",
        )
        .await;
        return Ok(());
    }

    let iface = state.interface_name();
    let response = resolution::format_peer_list(&peers, iface);
    send::send_html(client, chat_id, &response).await
}

pub(crate) async fn handle_enable(
    ctx: &mut PeerTransitionCtx<'_>,
    peer_name: Option<&str>,
) -> Result<(), String> {
    let action = PeerAction::Enable;
    perform_peer_transition(ctx, peer_name, &action).await
}

pub(crate) async fn handle_disable(
    ctx: &mut PeerTransitionCtx<'_>,
    peer_name: Option<&str>,
) -> Result<(), String> {
    let action = PeerAction::Disable;
    perform_peer_transition(ctx, peer_name, &action).await
}

/// Context bundle for peer enable/disable transitions. Collapses seven raw
/// parameters into a single typed argument so each call site reads clearly.
pub(crate) struct PeerTransitionCtx<'a> {
    pub(crate) client: &'a TelegramClient,
    pub(crate) chat_id: i64,
    pub(crate) state: &'a mut SystemState,
    pub(crate) user_id: i64,
    pub(crate) wake_tx: &'a mpsc::Sender<()>,
}

/// Per-action configuration for the shared enable/disable handler. Encodes
/// the display strings, typing indicator, and short-circuit logic for each
/// transition direction without exposing branching at every call site.
pub(crate) enum PeerAction {
    Enable,
    Disable,
}

impl PeerAction {
    fn target(&self) -> DesiredState {
        match self {
            Self::Enable => DesiredState::Enabled,
            Self::Disable => DesiredState::Disabled,
        }
    }

    /// Short-circuit when the peer is already in the target state.
    /// Enable skips when active; disable skips when inactive.
    fn skip_when_already_in_target(&self, is_active: bool) -> bool {
        match self {
            Self::Enable => is_active,
            Self::Disable => !is_active,
        }
    }

    /// Whether to send a "typing" chat action before processing.
    fn show_typing(&self) -> bool {
        matches!(self, Self::Enable)
    }

    fn status_message(&self, peer_name: &str) -> String {
        match self {
            Self::Enable => format!("ℹ️ Your peer \"{peer_name}\" is already active."),
            Self::Disable => format!("ℹ️ Your peer \"{peer_name}\" is already inactive."),
        }
    }

    fn success_message(&self, peer_name: &str, iface: &str) -> String {
        let verb = match self {
            Self::Enable => "Enabled",
            Self::Disable => "Disabled",
        };
        let state = self.target().describe();
        format!(
            "<b>✅ Peer \"{peer_name}\" {verb}</b>\n\n\
             Your peer is now {state} on interface `{iface}`.",
        )
    }
}

impl DesiredState {
    fn describe(&self) -> &'static str {
        match self {
            DesiredState::Enabled => "active",
            DesiredState::Disabled => "disabled",
        }
    }
}

/// Shared path for `/enable` and `/disable`: resolve the target peer, check its
/// live presence on the interface, apply the desired-state change, wake the
/// monitor, and send a confirmation. Returns Ok(()) whether the transition
/// happened or was a no-op (peer already in the target state).
pub(crate) async fn perform_peer_transition(
    ctx: &mut PeerTransitionCtx<'_>,
    peer_name: Option<&str>,
    action: &PeerAction,
) -> Result<(), String> {
    // Resolve the peer. The returned reference gives us direct access to its
    // CIDR below, avoiding a second linear scan.
    let peer = match ctx.state.resolve_peer(ctx.user_id, peer_name) {
        Ok(p) => p,
        Err(err_msg) => {
            let body = send::peer_not_found_msg(&err_msg, ctx.state, ctx.user_id, "");
            let _ = send::send_html(ctx.client, ctx.chat_id, &body).await;
            return Ok(());
        }
    };
    // Borrow the peer's fields into owned locals so we can mutably borrow
    // `ctx.state` below without holding the immutable borrow on `peer`.
    let peer_name_str = peer.config.name.clone();
    let peer_cidr = peer.config.allowed_ips.clone();
    let is_active = crate::vpn::get_peer_status(ctx.state.interface_name(), &peer_cidr)
        .map(|(up, _)| up)
        .unwrap_or(false);

    if action.skip_when_already_in_target(is_active) {
        let _ = send::send_html(
            ctx.client,
            ctx.chat_id,
            &action.status_message(&peer_name_str),
        )
        .await;
        return Ok(());
    }

    if action.show_typing() {
        let _ = ctx.client.send_chat_action(ctx.chat_id, "typing").await;
    }

    ctx.state
        .set_desired_for_user(ctx.user_id, &peer_name_str, action.target());
    let _ = ctx.wake_tx.send(()).await;

    send::send_html(
        ctx.client,
        ctx.chat_id,
        &action.success_message(&peer_name_str, ctx.state.interface_name()),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::*;

    /// /enable resolves the peer and sends wake signal (without a real
    /// WireGuard interface we cannot exercise the "already active" guard).
    #[tokio::test]
    async fn test_handle_enable_sends_wake_signal() {
        let mut cfg = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let (_tx, mut rx) = tokio::sync::mpsc::channel::<()>(10);

        let mut ctx = PeerTransitionCtx {
            client: &TelegramClient::new("fake_token_for_test").await.unwrap(),
            chat_id: 999_999,
            state: &mut cfg,
            user_id: TEST_USER_ID,
            wake_tx: &_tx,
        };

        let _ = handle_enable(&mut ctx, Some("alice")).await;

        // Wake signal was sent.
        rx.try_recv().unwrap();
    }

    /// /disable short-circuits when peer is already inactive (no real WG iface).
    #[tokio::test]
    async fn test_handle_disable_short_circuits_when_inactive() {
        let mut cfg = make_state("alice", "10.0.0.2/32", TEST_USER_ID);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(10);

        let mut ctx = PeerTransitionCtx {
            client: &TelegramClient::new("fake_token_for_test").await.unwrap(),
            chat_id: 999_999,
            state: &mut cfg,
            user_id: TEST_USER_ID,
            wake_tx: &tx,
        };

        let result = handle_disable(&mut ctx, Some("alice")).await;

        // Function succeeds — peer was already inactive per kernel.
        assert!(result.is_ok());
        // No wake signal sent.
        drop(tx);
        assert!(rx.try_recv().is_err());
    }
}
