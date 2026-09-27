//! Rust mirrors of the Postgres ENUM types (see `migrations/0001_*.sql`).
//!
//! The core enums carry no persistence derives, so the adapter defines its
//! own `sqlx::Type`s and converts at the boundary.  sqlx binds and decodes
//! these directly as `session_status` / `revocation_scope` /
//! `revocation_reason` — no text casts in SQL.

use auth_lib::authentication::SessionStatus;
use auth_lib::token::RevocationReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "session_status", rename_all = "snake_case")]
pub(crate) enum PgSessionStatus {
    Active,
    Revoked,
    Compromised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "revocation_scope", rename_all = "snake_case")]
pub(crate) enum PgRevocationScope {
    Session,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "revocation_reason", rename_all = "snake_case")]
pub(crate) enum PgRevocationReason {
    Logout,
    LogoutAll,
    Evicted,
    TokenReuse,
    IpMismatch,
    Compromised,
    Administrative,
    PasswordChanged,
    AccountDisabled,
    AccountDeleted,
}

impl From<SessionStatus> for PgSessionStatus {
    fn from(s: SessionStatus) -> Self {
        match s {
            SessionStatus::Active => Self::Active,
            SessionStatus::Revoked => Self::Revoked,
            SessionStatus::Compromised => Self::Compromised,
        }
    }
}

impl From<PgSessionStatus> for SessionStatus {
    fn from(s: PgSessionStatus) -> Self {
        match s {
            PgSessionStatus::Active => Self::Active,
            PgSessionStatus::Revoked => Self::Revoked,
            PgSessionStatus::Compromised => Self::Compromised,
        }
    }
}

impl From<RevocationReason> for PgRevocationReason {
    fn from(r: RevocationReason) -> Self {
        match r {
            RevocationReason::Logout => Self::Logout,
            RevocationReason::LogoutAll => Self::LogoutAll,
            RevocationReason::Evicted => Self::Evicted,
            RevocationReason::TokenReuse => Self::TokenReuse,
            RevocationReason::IpMismatch => Self::IpMismatch,
            RevocationReason::Compromised => Self::Compromised,
            RevocationReason::Administrative => Self::Administrative,
            RevocationReason::PasswordChanged => Self::PasswordChanged,
            RevocationReason::AccountDisabled => Self::AccountDisabled,
            RevocationReason::AccountDeleted => Self::AccountDeleted,
        }
    }
}

impl From<PgRevocationReason> for RevocationReason {
    fn from(r: PgRevocationReason) -> Self {
        match r {
            PgRevocationReason::Logout => Self::Logout,
            PgRevocationReason::LogoutAll => Self::LogoutAll,
            PgRevocationReason::Evicted => Self::Evicted,
            PgRevocationReason::TokenReuse => Self::TokenReuse,
            PgRevocationReason::IpMismatch => Self::IpMismatch,
            PgRevocationReason::Compromised => Self::Compromised,
            PgRevocationReason::Administrative => Self::Administrative,
            PgRevocationReason::PasswordChanged => Self::PasswordChanged,
            PgRevocationReason::AccountDisabled => Self::AccountDisabled,
            PgRevocationReason::AccountDeleted => Self::AccountDeleted,
        }
    }
}
