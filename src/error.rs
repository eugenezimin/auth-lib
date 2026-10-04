//! Auth-domain error type — the shared kernel used by every context.
//!
//! Adapters (database, cache, …) report their own failures through
//! [`AuthError::Storage`] so the core never depends on a driver's error type.

use crate::config::ConfigError;

// ── Error type ────────────────────────────────────────────────────────────────

/// All errors that can arise from auth operations.
#[derive(Debug)]
pub enum AuthError {
    /// A user with the given email already exists.
    EmailAlreadyTaken,

    /// A user with the given username already exists.
    UsernameAlreadyTaken,

    /// The supplied email address did not pass format validation.
    InvalidEmail(String),

    /// The supplied password did not meet complexity requirements.
    WeakPassword(String),

    /// Credentials were valid but the account has been deactivated.
    AccountDisabled,

    /// Credentials were valid but the account has not been verified.
    AccountNotVerified,

    /// Password hashing or verification failed.
    HashingError(String),

    /// A persistence adapter reported a failure.
    Storage(String),

    /// The library was misconfigured (bad value, missing port, …).
    Config(String),

    /// A catch-all for unexpected internal failures.
    Internal(String),

    /// A role with the given name already exists.
    RoleAlreadyExists,

    /// The user already has the role being assigned.
    RoleAlreadyAssigned,

    /// The user does not have the role being revoked.
    RoleNotAssigned,

    /// No user was found for the given identifier.
    UserNotFound,

    /// Email/password combination did not match.
    InvalidCredentials,

    /// JWT signing or encoding failed.
    TokenCreationError(String),

    /// The supplied JWT is invalid, expired, or unrecognised.
    InvalidToken(String),

    /// The token has been explicitly revoked, or its session has ended.
    TokenRevoked,

    /// The session passed its idle timeout or absolute lifetime.
    SessionExpired,

    /// Token reuse or an IP mismatch was detected; the session is now
    /// marked compromised and the user must log in again.
    SessionCompromised,

    /// The operation belongs to an authorization model that the configured
    /// `AUTH_AUTHZ_MODE` does not enable.
    AuthzModeDisabled(&'static str),

    /// No role with the given identifier.
    RoleNotFound,

    /// No permission with the given code.
    PermissionNotFound,

    /// A permission with the given code already exists.
    PermissionAlreadyExists,

    /// A role or permission code does not match `^[a-z][a-z0-9_.:-]*$`.
    InvalidCode(String),

    /// A permission value does not fit the permission's kind.
    InvalidPermissionValue(String),

    /// A cluster message failed authentication or validation (bad MAC,
    /// stale timestamp, replay, unknown sender).
    ClusterMessageRejected(String),

    /// A peer could not be reached (returned by host transports).
    ClusterUnreachable(String),
}

// ── Display ───────────────────────────────────────────────────────────────────

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmailAlreadyTaken => write!(f, "email address is already registered"),
            Self::UsernameAlreadyTaken => write!(f, "username is already taken"),
            Self::InvalidEmail(reason) => write!(f, "invalid email address: {reason}"),
            Self::WeakPassword(reason) => {
                write!(f, "password does not meet requirements: {reason}")
            }
            Self::AccountDisabled => write!(f, "account is disabled"),
            Self::AccountNotVerified => write!(f, "account has not been verified"),
            Self::HashingError(msg) => write!(f, "password hashing error: {msg}"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
            Self::RoleAlreadyExists => write!(f, "role name or code already exists"),
            Self::RoleAlreadyAssigned => write!(f, "user already has this role"),
            Self::RoleNotAssigned => write!(f, "user does not have this role"),
            Self::UserNotFound => write!(f, "no user found with the given identifier"),
            Self::InvalidCredentials => write!(f, "invalid email or password"),
            Self::TokenCreationError(msg) => write!(f, "token creation error: {msg}"),
            Self::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            Self::TokenRevoked => write!(f, "token has been revoked"),
            Self::SessionExpired => write!(f, "session has expired"),
            Self::SessionCompromised => write!(f, "session has been compromised"),
            Self::AuthzModeDisabled(what) => {
                write!(
                    f,
                    "{what} is not enabled by the configured authorization mode"
                )
            }
            Self::RoleNotFound => write!(f, "role not found"),
            Self::PermissionNotFound => write!(f, "permission not found"),
            Self::PermissionAlreadyExists => write!(f, "permission code already exists"),
            Self::InvalidCode(reason) => write!(f, "invalid code: {reason}"),
            Self::InvalidPermissionValue(reason) => {
                write!(f, "invalid permission value: {reason}")
            }
            Self::ClusterMessageRejected(reason) => {
                write!(f, "cluster message rejected: {reason}")
            }
            Self::ClusterUnreachable(reason) => write!(f, "cluster peer unreachable: {reason}"),
        }
    }
}

// ── std::error::Error ─────────────────────────────────────────────────────────

impl std::error::Error for AuthError {}

// ── Conversions ───────────────────────────────────────────────────────────────

impl From<ConfigError> for AuthError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e.to_string())
    }
}
