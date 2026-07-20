//! Per-peer timeout checks.
//!
//! Each function inspects a [`PeerState`] against a deadline and, if the
//! deadline has passed, mutates the peer into the disabled state and returns
//! a notification event describing what happened.

use std::time::{Duration, SystemTime};

use tracing::info;

use crate::state::*;

use super::types::*;

/// Check whether the peer has exceeded the first-handshake timeout.
///
/// Drives the timeout off `ps.first_seen_at` rather than the kernel-reported
/// `last_handshake`, because lib-wg wraps "no handshake" into `UNIX_EPOCH`
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

/// Check whether the session has been idle past the threshold.
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
