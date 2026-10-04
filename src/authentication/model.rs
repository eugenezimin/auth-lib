//! Authentication domain models — sessions, generations, credentials and
//! token pairs.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::authentication::repository`]
//! - Refresh policy       → [`crate::authentication::policy`]
//! - Service contract     → [`crate::authentication::service`]

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::token::model::RevocationReason;

/// Lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SessionStatus {
    Active,
    /// Ended normally (logout, eviction, administrative).
    Revoked,
    /// Ended because of token reuse, IP mismatch or a theft report.
    Compromised,
}

/// One login on one device.  Every timestamp is assigned by the store.
#[derive(Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Random per-session secret mixed into refresh-token MACs.
    pub secret: Vec<u8>,
    pub status: SessionStatus,
    pub end_reason: Option<RevocationReason>,
    pub created_ip: IpAddr,
    pub user_agent: Option<String>,
    pub current_generation: u32,
    pub created_at: DateTime<Utc>,
    /// Pushed forward on every refresh.
    pub idle_expires_at: DateTime<Utc>,
    /// Hard cap; never moves.
    pub absolute_expires_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// One token rotation within a session.  Every timestamp is assigned by the
/// store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGeneration {
    pub session_id: Uuid,
    pub generation: u32,
    /// The generation's own ID, used as the access token's `jti`.
    pub access_jti: Uuid,
    pub issued_ip: IpAddr,
    pub issued_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    /// Set when the next generation is issued.
    pub superseded_at: Option<DateTime<Utc>>,
}

/// Ready-to-insert session.  The store assigns the ID and every timestamp;
/// `created_ip` is also the first generation's `issued_ip`.
#[derive(Clone)]
pub struct NewSession {
    pub user_id: Uuid,
    pub secret: Vec<u8>,
    pub created_ip: IpAddr,
    pub user_agent: Option<String>,
}

/// Durations the store adds to its own clock when it creates or rotates a
/// session.  The core never sends instants — the store is the time source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLifetimes {
    /// `idle_expires_at = now + idle_timeout`, reset on every rotation.
    pub idle_timeout: Duration,
    /// `absolute_expires_at = created_at + absolute_timeout`.
    pub absolute_timeout: Duration,
    /// `access_expires_at = issued_at + access_ttl` for each generation.
    pub access_ttl: Duration,
    /// Generations kept per session for reuse detection.
    pub history_size: u32,
}

impl SessionLifetimes {
    pub fn from_config(config: &AuthConfig) -> Self {
        Self {
            idle_timeout: config.session.idle_timeout,
            absolute_timeout: config.session.absolute_timeout,
            access_ttl: config.jwt.access_token_ttl,
            history_size: config.session.history_size,
        }
    }
}

/// Everything the refresh policy needs, read in one go.
#[derive(Debug, Clone)]
pub struct RefreshSnapshot {
    pub session: Session,
    /// The requested generation, if still within history.
    pub presented: Option<SessionGeneration>,
    /// The session's current generation.
    pub current: Option<SessionGeneration>,
    /// The store's clock at read time — the policy's "now".
    pub now: DateTime<Utc>,
}

/// Result of [`SessionRepository::rotate`](crate::authentication::SessionRepository::rotate).
// `Rotated` is the common case and is consumed immediately; boxing it would
// only add an allocation per refresh.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum RotateOutcome {
    /// The new generation was stored; both values are as persisted.
    Rotated {
        session: Session,
        generation: SessionGeneration,
    },
    /// The session moved on (concurrent rotation) or is no longer active.
    Conflict,
}

/// Request metadata supplied by the host.  The host is responsible for
/// extracting the real client IP (e.g. from trusted proxy headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientContext {
    pub ip: IpAddr,
    pub user_agent: Option<String>,
}

/// Credentials supplied on login.
#[derive(Clone)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

/// Access + refresh tokens issued on login / refresh.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenPair {
    pub session_id: Uuid,
    pub access_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_token: String,
    /// When the session will end if not refreshed: min(idle, absolute).
    pub refresh_expires_at: DateTime<Utc>,
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("secret", &REDACTED)
            .field("status", &self.status)
            .field("end_reason", &self.end_reason)
            .field("created_ip", &self.created_ip)
            .field("user_agent", &self.user_agent)
            .field("current_generation", &self.current_generation)
            .field("created_at", &self.created_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("ended_at", &self.ended_at)
            .finish()
    }
}

impl std::fmt::Debug for NewSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSession")
            .field("user_id", &self.user_id)
            .field("secret", &REDACTED)
            .field("created_ip", &self.created_ip)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("email", &self.email)
            .field("password", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPair")
            .field("session_id", &self.session_id)
            .field("access_token", &REDACTED)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &REDACTED)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}
