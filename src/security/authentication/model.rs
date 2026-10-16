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

/// What a login produced: tokens, or a request for a second factor.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The session is open.
    Tokens(TokenPair),
    /// The password matched; complete the login with
    /// [`complete_login`](crate::security::authentication::AuthenticationService::complete_login).
    SecondFactor(LoginChallenge),
}

impl LoginOutcome {
    /// The token pair, or [`AuthError::SecondFactorRequired`] when a second
    /// factor is needed.
    ///
    /// [`AuthError::SecondFactorRequired`]: crate::AuthError::SecondFactorRequired
    pub fn into_tokens(self) -> Result<TokenPair, crate::AuthError> {
        match self {
            Self::Tokens(pair) => Ok(pair),
            Self::SecondFactor(_) => Err(crate::AuthError::SecondFactorRequired),
        }
    }
}

/// A pending login waiting for a second factor.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginChallenge {
    /// Opaque, single-use token the client sends back with the code.
    pub challenge_token: String,
    pub expires_at: DateTime<Utc>,
    /// Methods the user may answer with (e.g. `totp`, `email`, `sms`,
    /// `recovery_code`), preferred first.
    pub methods: Vec<String>,
    /// Set when a code was already sent.
    pub delivery: Option<ChallengeDelivery>,
}

/// Where a one-time code was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeDelivery {
    /// `email` or `sms`.
    pub method: String,
    /// Masked destination, e.g. `j***@example.com` or `•••• 1234`.
    pub destination_hint: String,
    pub expires_at: DateTime<Utc>,
}

/// The second step of a login.
#[derive(Clone)]
pub struct SecondFactorProof {
    pub challenge_token: String,
    /// The method the code belongs to; `None` lets the gate pick.
    pub method: Option<String>,
    pub code: String,
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

impl std::fmt::Debug for LoginOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tokens(pair) => f.debug_tuple("Tokens").field(pair).finish(),
            Self::SecondFactor(c) => f.debug_tuple("SecondFactor").field(c).finish(),
        }
    }
}

impl std::fmt::Debug for LoginChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginChallenge")
            .field("challenge_token", &REDACTED)
            .field("expires_at", &self.expires_at)
            .field("methods", &self.methods)
            .field("delivery", &self.delivery)
            .finish()
    }
}

impl std::fmt::Debug for SecondFactorProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondFactorProof")
            .field("challenge_token", &REDACTED)
            .field("method", &self.method)
            .field("code", &REDACTED)
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
