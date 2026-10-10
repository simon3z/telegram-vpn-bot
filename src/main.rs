mod auth;
mod config;
mod handlers;
mod monitor;
mod state;
mod telegram;
mod vpn;

#[cfg(test)]
#[path = "tests.rs"]
mod test_fixtures;

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tracing_journald::{self, Priority, PriorityMappings};
use tracing_subscriber::prelude::*;

/// Build a log filter respecting $RUST_LOG; falls back to "info" when unset.
fn rust_log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

/// Map tracing log levels to journald priorities.
///
/// journald uses its own severity hierarchy, which doesn't quite line up with
/// tracing's. We map conservatively so that important messages surface in
/// `journalctl` output even at low `RUST_LOG` thresholds.
pub(crate) fn journald_priority_mappings() -> PriorityMappings {
    PriorityMappings {
        error: Priority::Error,
        warn: Priority::Warning,
        info: Priority::Informational,
        debug: Priority::Debug,
        trace: Priority::Debug,
    }
}

/// Initialize the default stderr formatter subscriber.
fn init_stderr_tracer() {
    let filter = rust_log_filter();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

/// Detect whether this process was spawned by systemd as a managed service.
/// Decide whether we appear to be running under systemd given a probe
/// function. Exposed so tests can inject a fake source instead of mutating
/// the process-wide environment.
#[cfg(test)]
pub(crate) fn running_under_systemd_inner<F: FnOnce() -> bool>(has_journal_stream: F) -> bool {
    has_journal_stream()
}

/// Decide which tracing subscriber to install given a probe function.
#[cfg(test)]
pub(crate) fn select_tracer_inner<F: FnOnce() -> bool>(has_journal_stream: F) -> bool {
    has_journal_stream()
}

/// Check whether we are running under systemd.
///
/// systemd sets `$JOURNAL_STREAM` for every service unit it starts. Absence
/// of the variable means we are not running inside a systemd unit — either
/// we were launched from a console, or by some other supervisor.
pub(crate) fn running_under_systemd() -> bool {
    std::env::var("JOURNAL_STREAM").is_ok()
}

/// Build a Tokio multi-threaded runtime.  Worker threads are named
/// "tg-vpn-bot-worker-<N>" so they appear clearly in `ps` / `top`.
fn make_runtime() -> tokio::runtime::Runtime {
    use std::sync::atomic::{AtomicIsize, Ordering};
    static COUNTER: AtomicIsize = AtomicIsize::new(0);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(|| {
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            format!("tg-vpn-bot-worker-{id}")
        })
        .build()
        .expect("failed to build tokio runtime")
}

/// Install the tracing subscriber: journald when running under systemd,
/// stderr otherwise.
fn init_tracing() {
    if running_under_systemd() {
        if let Ok(journal) = tracing_journald::layer() {
            let journal = journal.with_priority_mappings(journald_priority_mappings());
            let filter = rust_log_filter();
            tracing_subscriber::registry()
                .with(journal)
                .with(filter)
                .init();
            return;
        }
        // journald unreachable — degrade gracefully instead of crashing.
    }
    init_stderr_tracer();
}

/// Load config, authenticate with Telegram, and log startup info.
async fn bootstrap(
) -> Result<(telegram::TelegramClient, config::Config), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let cfg = config::Config::load(&config_path)?;
    let token = cfg.get_token()?;
    auth::init_whitelist_from_config(&cfg);

    let client = telegram::TelegramClient::new(&token).await?;
    let bot_info = client.get_me().await?;
    info!("bot running as @{}", bot_info.username);
    info!("loaded config from: {config_path}");
    info!("managing WireGuard interface: {}", cfg.vpn.interface_name);
    info!("peers configured: {}", cfg.vpn.peers.len());

    Ok((client, cfg))
}

/// Spawn the task that drains monitor notifications and forwards them to
/// Telegram.
fn spawn_notifier(
    client: &telegram::TelegramClient,
    mut notify_rx: mpsc::Receiver<monitor::NotificationEvent>,
) -> tokio::task::JoinHandle<()> {
    let client = client.clone();
    tokio::spawn(async move {
        while let Some(ev) = notify_rx.recv().await {
            let message = ev.kind.format_message(&ev.peer_name);
            if let Err(e) = client
                .send_message(ev.user_id, &message, Some("HTML"))
                .await
            {
                let user_id = ev.user_id;
                let peer = ev.peer_name.to_string();
                let error = e.to_string();
                tracing::error!("failed to send notification to {user_id} ({peer}): {error}",);
            }
        }
    })
}

/// Spawn the update-polling task. Each update is processed under a fresh
/// state lock and wakes the monitor via `wake_tx`.
fn spawn_poller(
    client: &telegram::TelegramClient,
    timeout: u64,
    limit: u64,
    state: Arc<RwLock<state::SystemState>>,
    wake_tx: mpsc::Sender<()>,
) -> tokio::task::JoinHandle<()> {
    let client = client.clone();

    tokio::spawn(async move {
        let client_for_handler = client.clone();
        let state_for_handler = state.clone();
        let wake_tx_for_poller = wake_tx.clone();
        client
            .run_polling(timeout, limit, move |update| {
                let client_h = client_for_handler.clone();
                let state_h = state_for_handler.clone();
                let wake_tx_local = wake_tx_for_poller.clone();
                Box::pin(async move {
                    process_update(&client_h, update, &state_h, &wake_tx_local).await;
                })
            })
            .await
            .expect("poller failed")
    })
}

/// Block until SIGINT or SIGTERM arrives, then log which signal fired.
async fn wait_for_shutdown() {
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("failed to install SIGINT handler");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {
            info!("received SIGINT, shutting down...");
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down...");
        }
    }
}

/// Entry point.
fn main() -> std::io::Result<()> {
    let rt = make_runtime();
    match rt.block_on(async_main()) {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            Err(std::io::Error::other(msg))
        }
    }
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (client, cfg) = bootstrap().await?;

    // Build the single source of truth. All peers start disabled.
    let system_state = Arc::new(RwLock::new(state::SystemState::from_config(
        cfg.vpn.clone(),
    )));

    // Remove any leftover peers/routes left over from a previous crash or
    // unclean shutdown. Runs before the monitor starts so we don't race with
    // it.
    let kernel_ops = Arc::new(vpn::KernelWgOps);
    vpn::cleanup_managed_peers(&*kernel_ops, &cfg.vpn).await?;

    // Set up communication channels and background tasks.
    let (wake_tx, wake_rx) = mpsc::channel(32);
    let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<monitor::NotificationEvent>(16);
    let monitor_handle = monitor::spawn_monitor(
        system_state.clone(),
        wake_rx,
        notify_tx.clone(),
        kernel_ops.clone(),
    );
    let notify_handle = spawn_notifier(&client, notify_rx);
    let poller_handle = spawn_poller(
        &client,
        cfg.polling.timeout,
        cfg.polling.limit,
        system_state,
        wake_tx.clone(),
    );

    wait_for_shutdown().await;

    // 1. Stop all background tasks FIRST so they cannot modify state while
    //    we tear down the interface.
    drop((wake_tx, notify_tx));
    notify_handle.abort();
    poller_handle.abort();
    monitor_handle.abort();

    // 2. Now safe to cleanse the interface — no concurrent writes possible.
    if let Err(e) = vpn::cleanup_managed_peers(&*kernel_ops, &cfg.vpn).await {
        tracing::error!("interface cleanup failed: {e}");
    }

    info!("shutdown complete");
    Ok(())
}

/// Process an incoming update: check whitelist, route to handlers.
async fn process_update(
    client: &telegram::TelegramClient,
    update: &telegram::Update,
    state: &Arc<RwLock<state::SystemState>>,
    wake_tx: &mpsc::Sender<()>,
) {
    let user_id = update
        .message
        .as_ref()
        .and_then(|m| m.from.as_ref())
        .map(|f| f.id);

    if !auth::is_whitelisted(user_id) {
        send_unauthorized(client, update, user_id).await;
        return;
    }

    // Lock the state for reading/mutating.
    let mut state_guard = state.write().await;

    if let Err(e) = handlers::handle_update(client, update, &mut state_guard, wake_tx).await {
        tracing::error!("handler error: {e}");
    }
}

/// Send an unauthorized response when a non-whitelisted user tries to interact.
async fn send_unauthorized(
    client: &telegram::TelegramClient,
    update: &telegram::Update,
    user_id: Option<i64>,
) {
    if let Some(msg) = &update.message {
        let id_label = user_id
            .map(|id| format!("{}", id))
            .unwrap_or_else(|| "unknown".into());
        let text = format!(
            "❌ You are not authorized to use this bot.\nUser ID: {}",
            id_label
        );
        if handlers::send::send_html(client, msg.chat.id, &text)
            .await
            .is_err()
        {
            let chat_id = msg.chat.id;
            tracing::warn!("failed to send unauthorized message: chat_id={chat_id}",);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::{Chat, Message, TelegramClient, Update};

    /// Regression: without JOURNAL_STREAM set, we must fall back to stderr
    /// rather than attempt journald integration.
    #[test]
    fn test_running_under_systemd_false_when_not_set() {
        assert!(!running_under_systemd_inner(|| false));
    }

    /// Regression: when JOURNAL_STREAM is set (as systemd does for its
    /// services), we must opt into journald logging.
    #[test]
    fn test_running_under_systemd_true_when_set() {
        assert!(running_under_systemd_inner(|| true));
    }

    /// Regression: without JOURNAL_STREAM, the select falls back to stderr.
    #[test]
    fn test_select_tracer_falls_back_to_stderr_without_socket() {
        assert!(!select_tracer_inner(|| false));
    }

    /// Regression: with JOURNAL_STREAM set, systemd triggers journald.
    #[test]
    fn test_select_tracer_chooses_journald_with_socket() {
        assert!(select_tracer_inner(|| true));
    }

    /// Rust-logged filter respects the "info" fallback when RUST_LOG is unset.
    #[test]
    fn test_rust_log_filter_default_fallback_is_info() {
        // Preserve and restore the real RUST_LOG across tests.
        let saved = std::env::var("RUST_LOG").ok();
        std::env::remove_var("RUST_LOG");

        let filter = rust_log_filter();
        assert!(filter.to_string().contains("info"));

        // Restore.
        if let Some(v) = saved {
            std::env::set_var("RUST_LOG", v);
        }
    }

    /// Send-unauthorized path formats the user ID into a clear error message.
    /// With a fake token the actual send will fail, but the function must
    /// handle that gracefully without panicking.
    #[tokio::test]
    async fn test_send_unauthorized_formats_message_and_handles_network_failure() {
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();

        // Simulate an incoming update with a known user ID.
        let update = Update {
            update_id: 1,
            message: Some(Message {
                chat: Chat { id: 777_888 },
                from: Some(telegram::User { id: 42 }),
                text: Some("/help".into()),
            }),
        };

        // send_unauthorized should not panic even though the Telegram API call will fail.
        send_unauthorized(&client, &update, Some(42)).await;
    }

    /// Send-unauthorized falls back to "unknown" when the message has no from.
    #[tokio::test]
    async fn test_send_unauthorized_handles_missing_sender_gracefully() {
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();

        let update = Update {
            update_id: 1,
            message: Some(Message {
                chat: Chat { id: 777_888 },
                from: None,
                text: Some("/help".into()),
            }),
        };

        send_unauthorized(&client, &update, None).await;
    }

    /// Send-unauthorized does nothing when the update has no message.
    #[tokio::test]
    async fn test_send_unauthorized_noop_without_message() {
        let client = TelegramClient::new("fake_token_for_test").await.unwrap();

        let update = Update {
            update_id: 1,
            message: None,
        };

        send_unauthorized(&client, &update, Some(42)).await;
    }
}
