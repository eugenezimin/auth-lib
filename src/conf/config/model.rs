//! Configuration data models.
//!
//! This module contains **only** plain data structures and the error type.
//! - Loader trait              → [`crate::conf::config::loader`]
//! - Built-in loaders / parsing → [`crate::conf::config::loaders`]
//!
//! The library deliberately knows nothing about databases or HTTP servers —
//! those are configured by the host application.

use std::time::Duration;

/// Root configuration object, passed explicitly to services / the facade.
///
/// Every key is optional here: the auth service needs the signing key and
/// refresh secret, while a service that only verifies access tokens needs
/// just the verifying keys.  Presence is checked where the key is used.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt: JwtConfig,
    pub session: SessionConfig,
    pub password: PasswordPolicy,
    pub authz: AuthzConfig,
}

/// Request attributes that must match for two refreshes of the same
/// generation to count as one client retrying (same-site grace and
/// cross-site forks, when an extension replicates sessions).  Default: IP
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetryMatch {
    pub ip: bool,
    pub user_agent: bool,
    /// The host-supplied [`ClientContext::fingerprint`](crate::security::authentication::ClientContext::fingerprint).
    pub fingerprint: bool,
}

impl Default for RetryMatch {
    fn default() -> Self {
        Self {
            ip: true,
            user_agent: false,
            fingerprint: false,
        }
    }
}

/// Authorization settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthzConfig {
    pub mode: AuthzMode,
}

/// Which authorization model is active — decides what goes into access
/// tokens and which authorization services are enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthzMode {
    /// Authentication only: no roles or permissions in tokens.
    None,
    /// Roles only; tokens carry role codes (`rol`).
    #[default]
    Rbac,
    /// Permissions only; tokens carry encoded permissions (`prm`, `pv`).
    Permissions,
    /// Roles bundle permissions; tokens carry role codes and the effective
    /// (merged) permissions.
    Combined,
}

impl AuthzMode {
    /// Roles are managed and put into tokens.
    pub fn uses_roles(self) -> bool {
        matches!(self, Self::Rbac | Self::Combined)
    }
    /// Permissions are managed and put into tokens.
    pub fn uses_permissions(self) -> bool {
        matches!(self, Self::Permissions | Self::Combined)
    }
    /// Roles can carry permission grants.
    pub fn role_grants(self) -> bool {
        self == Self::Combined
    }
}

/// Access-token (JWT) settings.
#[derive(Clone)]
pub struct JwtConfig {
    /// Ed25519 signing seed.  Only the auth service (the issuer) holds it.
    pub signing_key: Option<[u8; 32]>,
    /// Ed25519 verifying keys accepted for verification.  Several keys allow
    /// rotating the signing key without a lockstep deploy.  When empty, the
    /// key derived from `signing_key` is used.
    pub verifying_keys: Vec<[u8; 32]>,
    /// How long an access token is valid.
    pub access_token_ttl: Duration,
    /// Clock-skew tolerance when checking `exp`.
    pub leeway: Duration,
    /// Token issuer claim (`iss`).
    pub issuer: String,
}

/// Session and refresh-token settings.
#[derive(Clone)]
pub struct SessionConfig {
    /// Server-wide HMAC key for refresh tokens.  Auth service only.
    pub refresh_secret: Option<Vec<u8>>,
    /// A session ends if it is not refreshed within this window.
    pub idle_timeout: Duration,
    /// A session ends this long after login, regardless of activity.
    pub absolute_timeout: Duration,
    /// Token generations kept per session for reuse detection.
    pub history_size: u32,
    /// How long after a rotation the previous generation still receives
    /// the current pair (concurrent refreshes).
    pub refresh_grace: Duration,
    /// Treat a refresh from an IP other than the session's creating IP as
    /// token theft.
    pub ip_binding: bool,
    /// What must match for a repeated refresh to count as a retry.
    pub retry_match: RetryMatch,
    /// Maximum number of concurrent active sessions per user.
    pub max_sessions_per_user: u32,
}

/// Password complexity requirements enforced on registration / update.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_digit: bool,
}

#[derive(Debug)]
pub enum ConfigError {
    /// A required field / environment variable was not set.
    Missing(String),
    /// A value was present but could not be parsed into the expected type.
    Parse { key: String, reason: String },
}

/// A flat, fully optional snapshot of every configuration knob.
///
/// Keys and secrets are base64 strings (standard alphabet).  Fields left as
/// `None` fall back to the defaults in [`crate::conf::constants`].
#[derive(Clone, Default)]
pub struct RawConfig {
    pub jwt_signing_key: Option<String>,
    pub jwt_verifying_keys: Option<Vec<String>>,
    pub jwt_access_ttl_secs: Option<u64>,
    pub jwt_leeway_secs: Option<u64>,
    pub jwt_issuer: Option<String>,

    pub refresh_secret: Option<String>,
    pub session_idle_timeout_secs: Option<u64>,
    pub session_absolute_timeout_secs: Option<u64>,
    pub session_history_size: Option<u32>,
    pub refresh_grace_secs: Option<u64>,
    pub ip_binding: Option<bool>,
    pub max_sessions_per_user: Option<u32>,

    pub password_min_length: Option<usize>,
    pub password_require_uppercase: Option<bool>,
    pub password_require_digit: Option<bool>,

    /// `none` | `rbac` | `permissions` | `combined`.
    pub authz_mode: Option<String>,

    /// Comma set of `ip`, `user_agent`, `fingerprint`.
    pub refresh_retry_match: Option<String>,
}
