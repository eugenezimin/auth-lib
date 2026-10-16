//! Rust mirrors of the Postgres ENUM types (see `migrations/0001_*.sql`).
//!
//! The core enums carry no persistence derives, so the adapter defines its
//! own `sqlx::Type`s and converts at the boundary.  sqlx binds and decodes
//! these directly as `session_status` / `revocation_scope` /
//! `revocation_reason` — no text casts in SQL.

use z_auth::security::authorization::PermissionKind;
use z_auth::security::session::RevocationReason;
use z_auth::security::session::SessionStatus;
use z_auth::security::token::{KeyStatus, RevocationStatus};

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
    Token,
}

/// Kind of a catalog entry; `text`'s length cap lives in its own column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "permission_kind", rename_all = "snake_case")]
pub(crate) enum PgPermissionKind {
    Bool,
    Single,
    Multi,
    Text,
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
    RevokedTokenUsed,
    ConcurrentRefresh,
    SecondFactorChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "revocation_status", rename_all = "snake_case")]
pub(crate) enum PgRevocationStatus {
    Pending,
    Enforced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "verifying_key_status", rename_all = "snake_case")]
pub(crate) enum PgKeyStatus {
    Active,
    Revoked,
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
            RevocationReason::RevokedTokenUsed => Self::RevokedTokenUsed,
            RevocationReason::ConcurrentRefresh => Self::ConcurrentRefresh,
            RevocationReason::SecondFactorChanged => Self::SecondFactorChanged,
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
            PgRevocationReason::RevokedTokenUsed => Self::RevokedTokenUsed,
            PgRevocationReason::ConcurrentRefresh => Self::ConcurrentRefresh,
            PgRevocationReason::SecondFactorChanged => Self::SecondFactorChanged,
        }
    }
}

impl From<PermissionKind> for PgPermissionKind {
    fn from(k: PermissionKind) -> Self {
        match k {
            PermissionKind::Bool => Self::Bool,
            PermissionKind::Single => Self::Single,
            PermissionKind::Multi => Self::Multi,
            PermissionKind::Text { .. } => Self::Text,
        }
    }
}

impl From<PgRevocationStatus> for RevocationStatus {
    fn from(s: PgRevocationStatus) -> Self {
        match s {
            PgRevocationStatus::Pending => Self::Pending,
            PgRevocationStatus::Enforced => Self::Enforced,
        }
    }
}

impl From<PgKeyStatus> for KeyStatus {
    fn from(s: PgKeyStatus) -> Self {
        match s {
            PgKeyStatus::Active => Self::Active,
            PgKeyStatus::Revoked => Self::Revoked,
        }
    }
}

impl From<RevocationStatus> for PgRevocationStatus {
    fn from(s: RevocationStatus) -> Self {
        match s {
            RevocationStatus::Pending => Self::Pending,
            RevocationStatus::Enforced => Self::Enforced,
        }
    }
}

impl From<KeyStatus> for PgKeyStatus {
    fn from(s: KeyStatus) -> Self {
        match s {
            KeyStatus::Active => Self::Active,
            KeyStatus::Revoked => Self::Revoked,
        }
    }
}
