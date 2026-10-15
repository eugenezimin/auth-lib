//! Authentication domain models — client context, credentials and token
//! pairs.  Sessions themselves live in [`crate::security::session`].
//!
//! Contains **only** plain data structures.
//! - Refresh policy       → [`crate::security::authentication::policy`]
//! - Service contract     → [`crate::security::authentication::service`]

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::security::session::model::IssueContext;

/// Request metadata supplied by the host.  The host is responsible for
/// extracting the real client IP (e.g. from trusted proxy headers).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientContext {
    pub ip: IpAddr,
    pub user_agent: Option<String>,
    /// Stable, device-bound client identifier chosen by the host — e.g. a
    /// random device id kept in an HttpOnly cookie set at login.  Only its
    /// SHA-256 is stored; compared when `AUTH_REFRESH_RETRY_MATCH` includes
    /// `fingerprint`.
    pub fingerprint: Option<String>,
}

impl ClientContext {
    /// The stored form of this request: user agent truncated, fingerprint
    /// hashed.  `parent_jti` is the presented access token, if any.
    pub fn issue_context(&self, parent_jti: Option<Uuid>) -> IssueContext {
        IssueContext {
            ip: self.ip,
            user_agent: truncate_user_agent(self.user_agent.clone()),
            fingerprint_hash: self.fingerprint.as_deref().and_then(fingerprint_hash),
            parent_jti,
        }
    }

    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            user_agent: None,
            fingerprint: None,
        }
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }
}

impl std::fmt::Debug for ClientContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientContext")
            .field("ip", &self.ip)
            .field("user_agent", &self.user_agent)
            .field(
                "fingerprint",
                &self.fingerprint.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
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

/// Cap a client-supplied user agent at
/// [`MAX_USER_AGENT_LEN`](crate::conf::constants::MAX_USER_AGENT_LEN) bytes,
/// cutting on a character boundary.
pub(crate) fn truncate_user_agent(user_agent: Option<String>) -> Option<String> {
    user_agent.map(|mut ua| {
        if ua.len() > crate::conf::constants::MAX_USER_AGENT_LEN {
            let mut end = crate::conf::constants::MAX_USER_AGENT_LEN;
            while !ua.is_char_boundary(end) {
                end -= 1;
            }
            ua.truncate(end);
        }
        ua
    })
}

/// SHA-256 of a client fingerprint.  Without the `crypto` feature
/// fingerprints are not stored (and never match).
#[cfg(feature = "crypto")]
fn fingerprint_hash(fingerprint: &str) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    Some(Sha256::digest(fingerprint.as_bytes()).into())
}

#[cfg(not(feature = "crypto"))]
fn fingerprint_hash(_fingerprint: &str) -> Option<[u8; 32]> {
    None
}
