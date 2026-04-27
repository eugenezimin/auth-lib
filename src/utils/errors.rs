/// Auth-domain error types.
///
/// This module defines every error variant that auth operations can produce.
/// `impl` blocks (e.g. `Display`, `Error`, `From`) belong here too because
/// this is the *utils* layer — the right home for cross-cutting concerns.

// ── Error type ────────────────────────────────────────────────────────────────

/// All errors that can arise from auth-service operations.
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

    /// An unexpected database error occurred.
    DatabaseError(String),

    /// A catch-all for unexpected internal failures.
    Internal(String),

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

    /// The token has been explicitly revoked (blocklist hit).
    TokenRevoked,
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
            Self::DatabaseError(msg) => write!(f, "database error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
            Self::RoleAlreadyAssigned => write!(f, "user already has this role"),
            Self::RoleNotAssigned => write!(f, "user does not have this role"),
            Self::UserNotFound => write!(f, "no user found with the given identifier"),
            Self::InvalidCredentials => write!(f, "invalid email or password"),
            Self::TokenCreationError(msg) => write!(f, "token creation error: {msg}"),
            Self::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            Self::TokenRevoked => write!(f, "token has been revoked"),
        }
    }
}

// ── std::error::Error ─────────────────────────────────────────────────────────

impl std::error::Error for AuthError {}
