use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::state::*;

use super::health;
use super::reconcile;
use super::types::*;

/// Spawn the monitoring loop as a background task.
///
/// Returns a handle the caller can use to abort the task. The loop accesses
/// [`SystemState`] via an [`Arc`]`<`[`RwLock`]`<..>>` — command handlers
/// receive a clone of this arc and mutate `desired` through it, then wake
/// the monitor via the provided channel.
pub fn spawn_monitor(
    state: Arc<RwLock<SystemState>>,
    mut wake_rx: mpsc::Receiver<WakeSignal>,
    notify_tx: mpsc::Sender<NotificationEvent>,
) -> MonitorHandle {
    let handle = tokio::spawn(async move {
        let initial = state.read().await;
        info!(
            "monitor started: poll_interval={}s, \
             first_handshake_timeout={}min, idle_timeout={}min",
            poll_interval(&initial.config).as_secs(),
            first_handshake_timeout_secs(&initial.config).as_secs() / 60,
            IDLE_TIMEOUT_SECS / 60,
        );
        drop(initial);
        run_monitor_loop(state, &mut wake_rx, notify_tx).await;
    });

    MonitorHandle { handle }
}

/// Main monitoring loop. Runs until the system state is dropped or the task
/// is aborted.
async fn run_monitor_loop(
    state: Arc<RwLock<SystemState>>,
    wake_rx: &mut mpsc::Receiver<WakeSignal>,
    notify_tx: mpsc::Sender<NotificationEvent>,
) {
    let (iface_name, poll_interval, first_hs_timeout) = {
        let s = state.read().await;
        (
            s.config.interface_name.clone(),
            crate::state::poll_interval(&s.config),
            crate::state::first_handshake_timeout_secs(&s.config),
        )
    };
    let idle_timeout = Duration::from_secs(IDLE_TIMEOUT_SECS);

    let mut next_wake = tokio::time::Instant::now() + poll_interval;

    loop {
        // Wait for either the poll timer or an immediate wake signal.
        tokio::select! {
            _ = tokio::time::sleep_until(next_wake) => {}
            _ = wake_rx.recv() => {}
        }

        // Drain any accumulated wake signals.
        while wake_rx.try_recv().is_ok() {}

        // Run the full cycle: sync actual state, health checks, then reconcile.
        let events = {
            let mut s = state.write().await;
            run_full_cycle_inner(&mut s, &iface_name, &first_hs_timeout, &idle_timeout).await
        };

        // Dispatch events to users via Telegram.
        for ev in events {
            if let Err(e) = notify_tx.send(ev).await {
                warn!("notification channel closed: error={e}");
                break;
            }
        }

        // Schedule the next poll cycle.
        next_wake = tokio::time::Instant::now() + poll_interval;
    }
}

/// Run one full poll cycle: sync VPN connection state, run health checks,
/// then reconcile declared intent vs reality. Returns a vector of notification
/// events to dispatch.
async fn run_full_cycle_inner(
    state: &mut SystemState,
    iface_name: &str,
    first_hs_timeout: &Duration,
    idle_timeout: &Duration,
) -> Vec<NotificationEvent> {
    let snapshot = PollSnapshot::capture(iface_name).await;

    // Phase A: Sync VPN connection state from snapshot.
    sync_vpn_connection(state, &snapshot);

    // Phase B: Health checks. May modify desired state.
    let health_events =
        health::run_health_checks(state, &snapshot, first_hs_timeout, idle_timeout).await;

    // Phase C: Reconcile. Align desired ↔ actual. No notifications are produced here.
    reconcile::reconcile_all(state, &snapshot).await;

    health_events
}

/// Sync VPN connection state from the captured snapshot.
fn sync_vpn_connection(state: &mut SystemState, snapshot: &PollSnapshot) {
    let latest_handshake = snapshot.latest_handshake();
    let connected = snapshot.has_any_peer() && latest_handshake.is_some();
    state.vpn_connection = if connected {
        VpnConnectionState::Connected {
            last_handshake: latest_handshake.unwrap(),
        }
    } else {
        VpnConnectionState::Disconnected
    };
}
