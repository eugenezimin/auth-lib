//! PostgreSQL implementation of z-auth-mfa's [`MfaRepository`].  All SQL
//! lives in [`mfa_queries`](super::mfa_queries).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use z_auth::AuthError;
use z_auth_mfa::model::{
    Challenge, Factor, LockState, NewChallenge, NewCode, NewFactor, SendOutcome,
};
use z_auth_mfa::repository::{CodeLimits, MfaRepository};

use super::mfa_queries as q;
use super::mfa_row::{
    ChallengeRow, FactorRow, LockRow, PgMfaMethod, PgTotpAlgorithm, RefusalRow, failures,
};
use crate::errors::map_sqlx_error;

/// PostgreSQL-backed second-factor store (see
/// `migrations_mfa/2001_mfa_schema.sql`).
pub struct PgMfaRepository {
    pool: PgPool,
}

impl PgMfaRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Classify a refused `SET_*_CODE`.
    async fn refusal(
        &self,
        query: &'static str,
        id: Uuid,
        limits: CodeLimits,
    ) -> Result<SendOutcome, AuthError> {
        let row: Option<RefusalRow> = sqlx::query_as(query)
            .bind(id)
            .bind(limits.resend_after)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(match row {
            Some(r) if r.usable == Some(true) && r.too_soon == Some(true) => SendOutcome::TooSoon,
            Some(r) if r.usable == Some(true) => SendOutcome::LimitReached,
            _ => SendOutcome::NotFound,
        })
    }
}

fn to_db_count(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn to_db_step(step: u64) -> Result<i64, AuthError> {
    i64::try_from(step).map_err(|_| AuthError::Internal("TOTP step out of range".into()))
}

fn lock_state(row: LockRow) -> LockState {
    LockState {
        failures: failures(row.failures),
        locked_until: row.locked_until,
        now: row.db_now,
    }
}

#[async_trait]
impl MfaRepository for PgMfaRepository {
    async fn list_factors(&self, user_id: Uuid) -> Result<Vec<Factor>, AuthError> {
        let rows: Vec<FactorRow> = sqlx::query_as(q::LIST_FACTORS)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn find_factor(
        &self,
        factor_id: Uuid,
    ) -> Result<Option<(Factor, DateTime<Utc>)>, AuthError> {
        let row: Option<FactorRow> = sqlx::query_as(q::FIND_FACTOR)
            .bind(factor_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(|r| {
            let now = r.db_now;
            Factor::try_from(r).map(|f| (f, now))
        })
        .transpose()
    }

    async fn insert_pending_factor(
        &self,
        factor: NewFactor,
        ttl: Duration,
    ) -> Result<Factor, AuthError> {
        let method = PgMfaMethod::from(factor.method);
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        sqlx::query(q::DELETE_PENDING_FACTOR)
            .bind(factor.user_id)
            .bind(method)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let totp = factor.totp;
        let row: FactorRow = sqlx::query_as(q::INSERT_PENDING_FACTOR)
            .bind(factor.id)
            .bind(factor.user_id)
            .bind(method)
            .bind(&factor.label)
            .bind(&factor.secret_sealed)
            .bind(totp.map(|t| PgTotpAlgorithm::from(t.algorithm)))
            .bind(totp.map(|t| i16::try_from(t.digits).unwrap_or(i16::MAX)))
            .bind(totp.map(|t| i32::try_from(t.period_secs).unwrap_or(i32::MAX)))
            .bind(&factor.destination_sealed)
            .bind(&factor.destination_hint)
            .bind(ttl)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        row.try_into()
    }

    async fn activate_factor(
        &self,
        factor_id: Uuid,
        user_id: Uuid,
        used_step: Option<u64>,
    ) -> Result<bool, AuthError> {
        let step = used_step.map(to_db_step).transpose()?;
        let result = sqlx::query(q::ACTIVATE_FACTOR)
            .bind(factor_id)
            .bind(user_id)
            .bind(step)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_factor(&self, factor_id: Uuid, user_id: Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(q::DELETE_FACTOR)
            .bind(factor_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn advance_totp_step(&self, factor_id: Uuid, step: u64) -> Result<bool, AuthError> {
        let result = sqlx::query(q::ADVANCE_TOTP_STEP)
            .bind(factor_id)
            .bind(to_db_step(step)?)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_factor_used(&self, factor_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(q::MARK_FACTOR_USED)
            .bind(factor_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_factor_code(
        &self,
        factor_id: Uuid,
        code_hash: [u8; 32],
        limits: CodeLimits,
    ) -> Result<SendOutcome, AuthError> {
        let stored: Option<DateTime<Utc>> = sqlx::query_scalar(q::SET_FACTOR_CODE)
            .bind(factor_id)
            .bind(code_hash.as_slice())
            .bind(limits.ttl)
            .bind(limits.resend_after)
            .bind(to_db_count(limits.max_sends))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        match stored {
            Some(expires_at) => Ok(SendOutcome::Stored { expires_at }),
            None => {
                self.refusal(q::FACTOR_CODE_REFUSAL, factor_id, limits)
                    .await
            }
        }
    }

    async fn record_factor_attempt(
        &self,
        factor_id: Uuid,
        max: u32,
    ) -> Result<Option<u32>, AuthError> {
        let attempts: Option<i32> = sqlx::query_scalar(q::RECORD_FACTOR_ATTEMPT)
            .bind(factor_id)
            .bind(to_db_count(max))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(attempts.map(|a| u32::try_from(a).unwrap_or(0)))
    }

    async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        code_hashes: &[[u8; 32]],
    ) -> Result<(), AuthError> {
        let hashes: Vec<Vec<u8>> = code_hashes.iter().map(|h| h.to_vec()).collect();
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        sqlx::query(q::DELETE_RECOVERY_CODES)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        if !hashes.is_empty() {
            sqlx::query(q::INSERT_RECOVERY_CODES)
                .bind(user_id)
                .bind(&hashes)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
        }
        tx.commit().await.map_err(map_sqlx_error)
    }

    async fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &[u8; 32],
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(q::CONSUME_RECOVERY_CODE)
            .bind(user_id)
            .bind(code_hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn count_recovery_codes(&self, user_id: Uuid) -> Result<u32, AuthError> {
        let n: i64 = sqlx::query_scalar(q::COUNT_RECOVERY_CODES)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    async fn create_challenge(
        &self,
        challenge: NewChallenge,
        ttl: Duration,
    ) -> Result<Challenge, AuthError> {
        let row: ChallengeRow = sqlx::query_as(q::INSERT_CHALLENGE)
            .bind(challenge.id)
            .bind(challenge.user_id)
            .bind(challenge.secret_hash.as_slice())
            .bind(challenge.created_ip)
            .bind(&challenge.user_agent)
            .bind(challenge.fingerprint_hash.map(|h| h.to_vec()))
            .bind(ttl)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.try_into()
    }

    async fn find_challenge(
        &self,
        challenge_id: Uuid,
    ) -> Result<Option<(Challenge, DateTime<Utc>)>, AuthError> {
        let row: Option<ChallengeRow> = sqlx::query_as(q::FIND_CHALLENGE)
            .bind(challenge_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        row.map(|r| {
            let now = r.db_now;
            Challenge::try_from(r).map(|c| (c, now))
        })
        .transpose()
    }

    async fn record_challenge_attempt(
        &self,
        challenge_id: Uuid,
        max: u32,
    ) -> Result<Option<u32>, AuthError> {
        let attempts: Option<i32> = sqlx::query_scalar(q::RECORD_CHALLENGE_ATTEMPT)
            .bind(challenge_id)
            .bind(to_db_count(max))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(attempts.map(|a| u32::try_from(a).unwrap_or(0)))
    }

    async fn set_challenge_code(
        &self,
        challenge_id: Uuid,
        code: NewCode,
        limits: CodeLimits,
    ) -> Result<SendOutcome, AuthError> {
        let stored: Option<DateTime<Utc>> = sqlx::query_scalar(q::SET_CHALLENGE_CODE)
            .bind(challenge_id)
            .bind(code.factor_id)
            .bind(code.code_hash.as_slice())
            .bind(limits.ttl)
            .bind(limits.resend_after)
            .bind(to_db_count(limits.max_sends))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        match stored {
            Some(expires_at) => Ok(SendOutcome::Stored { expires_at }),
            None => {
                self.refusal(q::CHALLENGE_CODE_REFUSAL, challenge_id, limits)
                    .await
            }
        }
    }

    async fn consume_challenge(&self, challenge_id: Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(q::CONSUME_CHALLENGE)
            .bind(challenge_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn lock_state(&self, user_id: Uuid) -> Result<LockState, AuthError> {
        let row: LockRow = sqlx::query_as(q::LOCK_STATE)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(lock_state(row))
    }

    async fn record_failure(
        &self,
        user_id: Uuid,
        window: Duration,
        threshold: u32,
        lock_for: Duration,
    ) -> Result<LockState, AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        sqlx::query(q::ENSURE_USER_STATE)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        let row: LockRow = sqlx::query_as(q::RECORD_FAILURE)
            .bind(user_id)
            .bind(window)
            .bind(to_db_count(threshold.max(1)))
            .bind(lock_for)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(lock_state(row))
    }

    async fn clear_failures(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(q::CLEAR_FAILURES)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn delete_all(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        for query in [
            q::DELETE_USER_CHALLENGES,
            q::DELETE_RECOVERY_CODES,
            q::CLEAR_FAILURES,
        ] {
            sqlx::query(query)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
        }
        let deleted = sqlx::query(q::DELETE_USER_FACTORS)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?
            .rows_affected();
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(deleted)
    }

    async fn purge(&self, retention: Duration) -> Result<u64, AuthError> {
        let n: i64 = sqlx::query_scalar(q::PURGE)
            .bind(retention)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}
