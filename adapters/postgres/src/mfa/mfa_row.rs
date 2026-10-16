//! Rows and enum types of the `mfa_` tables, and their conversion into
//! z-auth-mfa's models.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;
use z_auth_mfa::model::{
    Challenge, ChallengeCode, Factor, FactorStatus, MfaMethod, PendingCode, TotpAlgorithm,
    TotpParams,
};

use crate::rows::fingerprint_from_db;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "mfa_method", rename_all = "snake_case")]
pub(crate) enum PgMfaMethod {
    Totp,
    Email,
    Sms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "mfa_factor_status", rename_all = "snake_case")]
pub(crate) enum PgFactorStatus {
    Pending,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "mfa_totp_algorithm", rename_all = "snake_case")]
pub(crate) enum PgTotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<MfaMethod> for PgMfaMethod {
    fn from(m: MfaMethod) -> Self {
        match m {
            MfaMethod::Totp => Self::Totp,
            MfaMethod::Email => Self::Email,
            MfaMethod::Sms => Self::Sms,
        }
    }
}

impl From<PgMfaMethod> for MfaMethod {
    fn from(m: PgMfaMethod) -> Self {
        match m {
            PgMfaMethod::Totp => Self::Totp,
            PgMfaMethod::Email => Self::Email,
            PgMfaMethod::Sms => Self::Sms,
        }
    }
}

impl From<PgFactorStatus> for FactorStatus {
    fn from(s: PgFactorStatus) -> Self {
        match s {
            PgFactorStatus::Pending => Self::Pending,
            PgFactorStatus::Active => Self::Active,
        }
    }
}

impl From<TotpAlgorithm> for PgTotpAlgorithm {
    fn from(a: TotpAlgorithm) -> Self {
        match a {
            TotpAlgorithm::Sha1 => Self::Sha1,
            TotpAlgorithm::Sha256 => Self::Sha256,
            TotpAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

impl From<PgTotpAlgorithm> for TotpAlgorithm {
    fn from(a: PgTotpAlgorithm) -> Self {
        match a {
            PgTotpAlgorithm::Sha1 => Self::Sha1,
            PgTotpAlgorithm::Sha256 => Self::Sha256,
            PgTotpAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

pub(crate) fn hash_from_db(bytes: Vec<u8>) -> Result<[u8; 32], AuthError> {
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| AuthError::Storage("stored hash must be 32 bytes".into()))
}

fn count(v: i32) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

/// The `code_*` columns of a factor or challenge.
fn pending_code(
    hash: Option<Vec<u8>>,
    expires_at: Option<DateTime<Utc>>,
    sent_at: Option<DateTime<Utc>>,
    sends: i32,
    attempts: i32,
) -> Result<Option<PendingCode>, AuthError> {
    let (Some(hash), Some(expires_at), Some(sent_at)) = (hash, expires_at, sent_at) else {
        return Ok(None);
    };
    Ok(Some(PendingCode {
        code_hash: hash_from_db(hash)?,
        expires_at,
        sent_at,
        sends: count(sends),
        attempts: count(attempts),
    }))
}

/// A `mfa_factors` row plus `now()`.
#[derive(sqlx::FromRow)]
pub(crate) struct FactorRow {
    id: Uuid,
    user_id: Uuid,
    method: PgMfaMethod,
    status: PgFactorStatus,
    label: Option<String>,
    secret_sealed: Option<Vec<u8>>,
    totp_algorithm: Option<PgTotpAlgorithm>,
    totp_digits: Option<i16>,
    totp_period_secs: Option<i32>,
    last_used_step: Option<i64>,
    destination_sealed: Option<Vec<u8>>,
    destination_hint: Option<String>,
    code_hash: Option<Vec<u8>>,
    code_expires_at: Option<DateTime<Utc>>,
    code_sent_at: Option<DateTime<Utc>>,
    code_sends: i32,
    code_attempts: i32,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    confirmed_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    pub(crate) db_now: DateTime<Utc>,
}

impl TryFrom<FactorRow> for Factor {
    type Error = AuthError;

    fn try_from(r: FactorRow) -> Result<Self, AuthError> {
        let totp = match (r.totp_algorithm, r.totp_digits, r.totp_period_secs) {
            (Some(algorithm), Some(digits), Some(period)) => Some(TotpParams {
                algorithm: algorithm.into(),
                digits: u32::try_from(digits)
                    .map_err(|_| AuthError::Storage("negative totp_digits".into()))?,
                period_secs: u64::try_from(period)
                    .map_err(|_| AuthError::Storage("negative totp_period_secs".into()))?,
            }),
            _ => None,
        };
        Ok(Self {
            id: r.id,
            user_id: r.user_id,
            method: r.method.into(),
            status: r.status.into(),
            label: r.label,
            secret_sealed: r.secret_sealed,
            totp,
            last_used_step: r.last_used_step.and_then(|s| u64::try_from(s).ok()),
            destination_sealed: r.destination_sealed,
            destination_hint: r.destination_hint,
            code: pending_code(
                r.code_hash,
                r.code_expires_at,
                r.code_sent_at,
                r.code_sends,
                r.code_attempts,
            )?,
            created_at: r.created_at,
            expires_at: r.expires_at,
            confirmed_at: r.confirmed_at,
            last_used_at: r.last_used_at,
        })
    }
}

/// A `mfa_challenges` row plus `now()`.
#[derive(sqlx::FromRow)]
pub(crate) struct ChallengeRow {
    id: Uuid,
    user_id: Uuid,
    secret_hash: Vec<u8>,
    created_ip: IpAddr,
    user_agent: Option<String>,
    fingerprint_hash: Option<Vec<u8>>,
    attempts: i32,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    code_factor_id: Option<Uuid>,
    code_hash: Option<Vec<u8>>,
    code_expires_at: Option<DateTime<Utc>>,
    code_sent_at: Option<DateTime<Utc>>,
    code_sends: i32,
    code_attempts: i32,
    pub(crate) db_now: DateTime<Utc>,
}

impl TryFrom<ChallengeRow> for Challenge {
    type Error = AuthError;

    fn try_from(r: ChallengeRow) -> Result<Self, AuthError> {
        let code = match (
            r.code_factor_id,
            pending_code(
                r.code_hash,
                r.code_expires_at,
                r.code_sent_at,
                r.code_sends,
                r.code_attempts,
            )?,
        ) {
            (Some(factor_id), Some(code)) => Some(ChallengeCode { factor_id, code }),
            _ => None,
        };
        Ok(Self {
            id: r.id,
            user_id: r.user_id,
            secret_hash: hash_from_db(r.secret_hash)?,
            created_ip: r.created_ip,
            user_agent: r.user_agent,
            fingerprint_hash: fingerprint_from_db(r.fingerprint_hash)?,
            attempts: count(r.attempts),
            created_at: r.created_at,
            expires_at: r.expires_at,
            consumed_at: r.consumed_at,
            code,
        })
    }
}

/// `mfa_user_state` (or nothing) plus `now()`.
#[derive(sqlx::FromRow)]
pub(crate) struct LockRow {
    pub(crate) failures: Option<i32>,
    pub(crate) locked_until: Option<DateTime<Utc>>,
    pub(crate) db_now: DateTime<Utc>,
}

/// Why a code was not stored.
#[derive(sqlx::FromRow)]
pub(crate) struct RefusalRow {
    pub(crate) usable: Option<bool>,
    pub(crate) too_soon: Option<bool>,
}

pub(crate) fn failures(v: Option<i32>) -> u32 {
    v.map_or(0, count)
}
