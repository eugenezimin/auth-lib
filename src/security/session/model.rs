//! Session domain models — sessions, their generations, and why they end.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::security::session::repository`]
//! - Refresh policy       → [`crate::security::authentication::policy`]

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::conf::config::AuthConfig;

/// Why a session ended or a revocation was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RevocationReason {
    /// Single-session logout.
    Logout,
    /// Logout from every session of the user.
    LogoutAll,
    /// Oldest session closed to respect `max_sessions_per_user`.
    Evicted,
    /// A superseded refresh token was presented again.
    TokenReuse,
    /// A refresh came from an IP other than the session's creating IP.
    IpMismatch,
    /// Reported as stolen / leaked (e.g. via the revocation API).
    Compromised,
    /// Revoked by an administrator or an external system.
    Administrative,
    /// The user's password was changed; every earlier session is ended.
    PasswordChanged,
    /// The user account was deactivated.
    AccountDisabled,
    /// The user account was deleted.
    AccountDeleted,
    /// A token covered by a pending revocation was presented: the session is
    /// treated as compromised.
    RevokedTokenUsed,
    /// Federation mode: the losing access token of a benign refresh fork
    /// (two services rotated the same generation for the same client).
    /// Only that token is revoked; the session goes on.
    ConcurrentRefresh,
}

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
    /// The access token presented to obtain this generation (`None` for
    /// generation 1).  Tells concurrent rotations of the same generation
    /// apart from a stolen token used on a later one.
    pub parent_jti: Option<Uuid>,
    /// The client's user agent at issue time (truncated like the session's).
    pub issued_user_agent: Option<String>,
    /// SHA-256 of the client fingerprint at issue time, if one was given.
    pub fingerprint_hash: Option<[u8; 32]>,
    /// Federation mode: access-token ids of competing rotations of this
    /// generation that lost a benign fork.  Accepted like `access_jti`, so
    /// the client holding that pair can refresh once into the winning
    /// chain.  Always empty in the other modes.
    pub aliases: Vec<Uuid>,
}

impl SessionGeneration {
    /// The request attributes this generation was issued to.
    pub fn issued_to(&self) -> RequestTraits<'_> {
        RequestTraits {
            ip: self.issued_ip,
            user_agent: self.issued_user_agent.as_deref(),
            fingerprint_hash: self.fingerprint_hash.as_ref(),
        }
    }
}

/// The attributes compared by `AUTH_REFRESH_RETRY_MATCH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTraits<'a> {
    pub ip: IpAddr,
    pub user_agent: Option<&'a str>,
    pub fingerprint_hash: Option<&'a [u8; 32]>,
}

impl RequestTraits<'_> {
    /// Whether two requests count as the same client under `m`.  A missing
    /// fingerprint never matches when fingerprints are compared.
    pub fn same_client(
        &self,
        other: &RequestTraits<'_>,
        m: &crate::conf::config::RetryMatch,
    ) -> bool {
        (!m.ip || self.ip == other.ip)
            && (!m.user_agent || self.user_agent == other.user_agent)
            && (!m.fingerprint
                || (self.fingerprint_hash.is_some()
                    && self.fingerprint_hash == other.fingerprint_hash))
    }
}

/// Ready-to-insert session.  The store assigns the ID and every timestamp;
/// `created_ip` is also the first generation's `issued_ip`, `user_agent`
/// its `issued_user_agent`.
#[derive(Clone)]
pub struct NewSession {
    pub user_id: Uuid,
    pub secret: Vec<u8>,
    pub created_ip: IpAddr,
    pub user_agent: Option<String>,
    /// SHA-256 of the client fingerprint, stored on generation 1.
    pub fingerprint_hash: Option<[u8; 32]>,
}

/// Who a rotation issues the next generation to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueContext {
    pub ip: IpAddr,
    /// Already truncated to `MAX_USER_AGENT_LEN`.
    pub user_agent: Option<String>,
    pub fingerprint_hash: Option<[u8; 32]>,
    /// The access-token `jti` presented with the refresh.
    pub parent_jti: Option<Uuid>,
}

impl IssueContext {
    pub fn traits(&self) -> RequestTraits<'_> {
        RequestTraits {
            ip: self.ip,
            user_agent: self.user_agent.as_deref(),
            fingerprint_hash: self.fingerprint_hash.as_ref(),
        }
    }
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

/// Result of [`SessionRepository::rotate`](crate::security::session::SessionRepository::rotate).
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
