//! [`MfaRepository`] — the storage z-auth-mfa needs, implemented by the
//! host (e.g. `z_auth_postgres::PgMfaRepository`, feature `mfa`).
//!
//! As in z-auth's core, the store is the time source: callers pass
//! durations, never instants, and every timestamp is assigned by the store.
//! Methods documented as compare-and-swap must be atomic — concurrent
//! callers must not both succeed.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;

use crate::model::{Challenge, Factor, LockState, NewChallenge, NewCode, NewFactor, SendOutcome};

/// When a new one-time code may be stored on a factor or challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeLimits {
    /// How long the code stays valid.
    pub ttl: Duration,
    /// Minimum gap since the previous send.
    pub resend_after: Duration,
    /// Sends while codes stay valid; the count restarts once the latest
    /// code expired.
    pub max_sends: u32,
}

#[async_trait]
pub trait MfaRepository: Send + Sync {
    // ── Factors ──────────────────────────────────────────────────────────────

    /// Every factor of a user (pending ones included), oldest first.
    async fn list_factors(&self, user_id: Uuid) -> Result<Vec<Factor>, AuthError>;

    /// A factor plus the store's clock at read time.
    async fn find_factor(
        &self,
        factor_id: Uuid,
    ) -> Result<Option<(Factor, DateTime<Utc>)>, AuthError>;

    /// Insert a pending factor that expires after `ttl`, replacing any
    /// pending factor of the same user and method.
    async fn insert_pending_factor(
        &self,
        factor: NewFactor,
        ttl: Duration,
    ) -> Result<Factor, AuthError>;

    /// Compare-and-swap: a pending, unexpired factor of `user_id` becomes
    /// active (`confirmed_at` = now, its code cleared, `last_used_step`
    /// set when given).  `false` if it is not pending, expired or someone
    /// else's.  [`AuthError::SecondFactorAlreadyEnrolled`] if the user
    /// already has an active factor of this method.
    async fn activate_factor(
        &self,
        factor_id: Uuid,
        user_id: Uuid,
        used_step: Option<u64>,
    ) -> Result<bool, AuthError>;

    /// Delete a factor of `user_id`.  `false` if there was none.
    async fn delete_factor(&self, factor_id: Uuid, user_id: Uuid) -> Result<bool, AuthError>;

    /// Compare-and-swap: accept TOTP step `step` only if it is later than
    /// the factor's `last_used_step` (sets it and `last_used_at`).  `false`
    /// means the code was already used.
    async fn advance_totp_step(&self, factor_id: Uuid, step: u64) -> Result<bool, AuthError>;

    /// Record a use of an email / SMS factor (`last_used_at`) and clear its
    /// code.
    async fn mark_factor_used(&self, factor_id: Uuid) -> Result<(), AuthError>;

    /// Store a new code on a factor (enrollment confirmation or step-up)
    /// within `limits`; resets its attempt count.
    async fn set_factor_code(
        &self,
        factor_id: Uuid,
        code_hash: [u8; 32],
        limits: CodeLimits,
    ) -> Result<SendOutcome, AuthError>;

    /// Compare-and-swap: count one entry of the factor's current code if it
    /// is unexpired and below `max` attempts.  Returns the new count, or
    /// `None` when no code is usable.
    async fn record_factor_attempt(
        &self,
        factor_id: Uuid,
        max: u32,
    ) -> Result<Option<u32>, AuthError>;

    // ── Recovery codes ───────────────────────────────────────────────────────

    /// Replace a user's recovery codes (atomically) with these hashes.
    async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        code_hashes: &[[u8; 32]],
    ) -> Result<(), AuthError>;

    /// Compare-and-swap: mark an unused code of `user_id` with this hash
    /// used.  `false` if there is none.
    async fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &[u8; 32],
    ) -> Result<bool, AuthError>;

    /// Unused recovery codes of a user.
    async fn count_recovery_codes(&self, user_id: Uuid) -> Result<u32, AuthError>;

    // ── Login challenges ─────────────────────────────────────────────────────

    async fn create_challenge(
        &self,
        challenge: NewChallenge,
        ttl: Duration,
    ) -> Result<Challenge, AuthError>;

    /// A challenge plus the store's clock at read time.
    async fn find_challenge(
        &self,
        challenge_id: Uuid,
    ) -> Result<Option<(Challenge, DateTime<Utc>)>, AuthError>;

    /// Compare-and-swap: count one attempt if the challenge is unconsumed,
    /// unexpired and below `max` attempts.  Returns the new count, or
    /// `None` when it can take no more.
    async fn record_challenge_attempt(
        &self,
        challenge_id: Uuid,
        max: u32,
    ) -> Result<Option<u32>, AuthError>;

    /// Store a new email / SMS code on an unconsumed, unexpired challenge
    /// within `limits`.
    async fn set_challenge_code(
        &self,
        challenge_id: Uuid,
        code: NewCode,
        limits: CodeLimits,
    ) -> Result<SendOutcome, AuthError>;

    /// Compare-and-swap: mark the challenge consumed.  `false` if it
    /// already was (or expired).
    async fn consume_challenge(&self, challenge_id: Uuid) -> Result<bool, AuthError>;

    // ── Lockout ──────────────────────────────────────────────────────────────

    async fn lock_state(&self, user_id: Uuid) -> Result<LockState, AuthError>;

    /// Count one failed attempt.  Failures older than `window` start a new
    /// count; reaching `threshold` locks the user for `lock_for` (and
    /// restarts the count).
    async fn record_failure(
        &self,
        user_id: Uuid,
        window: Duration,
        threshold: u32,
        lock_for: Duration,
    ) -> Result<LockState, AuthError>;

    /// Forget a user's failures (after a successful proof).
    async fn clear_failures(&self, user_id: Uuid) -> Result<(), AuthError>;

    // ── Housekeeping ─────────────────────────────────────────────────────────

    /// Delete everything stored for a user (factors, recovery codes,
    /// challenges, lockout).  Returns the number of factors deleted.
    async fn delete_all(&self, user_id: Uuid) -> Result<u64, AuthError>;

    /// Delete challenges and pending factors that expired (or challenges
    /// consumed) more than `retention` ago, and lockout rows with nothing
    /// left to remember.  Returns the number of rows deleted.
    async fn purge(&self, retention: Duration) -> Result<u64, AuthError>;
}
