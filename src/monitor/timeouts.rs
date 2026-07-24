//! Per-peer timeout checks.
//!
//! Two independent watchdog timers run on every poll while a peer is enabled:
//!
//! 1. **Connection deadline** ([`check_first_handshake_timeout`]) — counts
//!    elapsed seconds since [`PeerState::first_seen_at`]. If no handshake
//!    arrives within the configured window (default 60 s, configurable via
//!    `vpn.first_handshake_timeout`), the peer is auto-disabled and the user
//!    receives a [`NotificationKind::FirstHandshakeTimeout`] notification.
//!
//! 2. **Idle watchdog** ([`check_idle_timeout`]) — counts elapsed seconds
//!    since [`PeerState::last_handshake`]. If the session goes quiet past the
//!    hard-coded 180 s threshold, the peer is auto-disabled and the user
//!    receives a [`NotificationKind::IdleDisconnected`] notification.
//!
//! Both timers read from `PeerState`, never from the kernel directly, so they
//! are immune to lib-wg quirks around `last_handshake` reporting.

use std::time::{Duration, SystemTime};

use tracing::info;

use crate::state::*;

use super::types::*;

/// Connection-deadline timer.
///
/// Counts elapsed seconds since [`PeerState::first_seen_at`]. Fires when the
/// configured window elapses without a successful handshake, at which point
/// the peer is auto-disabled and a [`NotificationKind::FirstHandshakeTimeout`]
/// event is returned.
///
/// Driven from `first_seen_at` rather than the kernel-reported
/// `last_handshake` because lib-wg wraps "no handshake" into `UNIX_EPOCH`,
/// which would otherwise fire immediately.
pub(crate) fn check_first_handshake_timeout(
    ps: &mut PeerState,
    now: SystemTime,
    first_hs_timeout: Duration,
) -> Option<NotificationEvent> {
    let first_seen = ps.first_seen_at?;
    let elapsed_secs = now.duration_since(first_seen).ok()?.as_secs();

    if elapsed_secs >= first_hs_timeout.as_secs() {
        info!(
            "first-handshake timeout exceeded: peer={}, elapsed_secs={}",
            ps.config.name, elapsed_secs
        );
        ps.first_seen_at = None;
        ps.last_handshake = None;
        ps.desired = DesiredState::Disabled;

        Some(NotificationEvent {
            user_id: ps.config.telegram_id,
            peer_name: ps.config.name.clone(),
            kind: NotificationKind::FirstHandshakeTimeout {
                elapsed_secs: first_hs_timeout.as_secs(),
            },
        })
    } else {
        None
    }
}

/// Idle-watchdog timer.
///
/// Counts elapsed seconds since [`PeerState::last_handshake`]. Fires when the
/// session has been quiet for longer than the threshold (hard-coded 180 s),
/// at which point the peer is auto-disabled and a
/// [`NotificationKind::IdleDisconnected`] event is returned.
pub(crate) fn check_idle_timeout(
    ps: &mut PeerState,
    now: SystemTime,
    idle_timeout: Duration,
) -> Option<NotificationEvent> {
    let last_handshake = ps.last_handshake?;
    let idle_elapsed = now.duration_since(last_handshake).ok()?.as_secs();

    if idle_elapsed >= idle_timeout.as_secs() {
        info!(
            "session idle timeout exceeded: peer={}, idle_elapsed={}s",
            ps.config.name, idle_elapsed
        );
        ps.first_seen_at = None;
        ps.last_handshake = None;
        ps.desired = DesiredState::Disabled;

        Some(NotificationEvent {
            user_id: ps.config.telegram_id,
            peer_name: ps.config.name.clone(),
            kind: NotificationKind::IdleDisconnected,
        })
    } else {
        None
    }
}
