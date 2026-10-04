//! Session repository port.
//!
//! Persistence contract for sessions and their token generations.
//! auth-lib ships **no implementation**; the host application provides one.
//! All refresh *policy* lives in the core — implementations only need to
//! make [`rotate`](SessionRepository::rotate) atomic.
//!
//! **The store is the time source.**  Every timestamp is assigned from the
//! store's own clock (`now()` in SQL); the core only supplies durations
//! ([`SessionLifetimes`], `retention`) and reads back what was persisted.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::authentication::model::{
    NewSession, RefreshSnapshot, RotateOutcome, Session, SessionGeneration, SessionLifetimes,
    SessionStatus,
};
use crate::error::AuthError;
use crate::token::model::RevocationReason;

#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Atomically insert a new active session and its generation 1, with
    /// store-assigned IDs and `now` taken once for both:
    ///
    /// - session: `created_at = now`, `idle_expires_at = now + idle_timeout`,
    ///   `absolute_expires_at = now + absolute_timeout`, `current_generation = 1`;
    /// - generation: `issued_ip = created_ip`, `issued_at = now`,
    ///   `access_expires_at = now + access_ttl`.
    async fn create(
        &self,
        session: NewSession,
        lifetimes: &SessionLifetimes,
    ) -> Result<(Session, SessionGeneration), AuthError>;

    /// Fetch a session by ID (any status).
    async fn find(&self, session_id: Uuid) -> Result<Option<Session>, AuthError>;

    /// Fetch one generation of a session, if still within history.
    async fn find_generation(
        &self,
        session_id: Uuid,
        generation: u32,
    ) -> Result<Option<SessionGeneration>, AuthError>;

    /// Read a session, its generation `generation`, its current generation
    /// and the store's current time — ideally in one round trip.
    /// `Ok(None)` if the session does not exist.
    async fn load_for_refresh(
        &self,
        session_id: Uuid,
        generation: u32,
    ) -> Result<Option<RefreshSnapshot>, AuthError>;

    /// Atomically advance a session by one generation:
    ///
    /// 1. only if the session is `active` **and** still at
    ///    `expected_generation` (otherwise return [`RotateOutcome::Conflict`]);
    /// 2. set `current_generation = expected + 1` and
    ///    `idle_expires_at = now + idle_timeout`;
    /// 3. stamp `superseded_at = now` on `expected_generation`;
    /// 4. insert the new generation (`issued_at = now`,
    ///    `access_expires_at = now + access_ttl`);
    /// 5. delete generations older than the newest `history_size`.
    async fn rotate(
        &self,
        session_id: Uuid,
        expected_generation: u32,
        issued_ip: IpAddr,
        lifetimes: &SessionLifetimes,
    ) -> Result<RotateOutcome, AuthError>;

    /// End an **active** session (`ended_at = now`).  Returns `false` if it
    /// was missing or already ended.
    async fn end(
        &self,
        session_id: Uuid,
        status: SessionStatus,
        reason: RevocationReason,
    ) -> Result<bool, AuthError>;

    /// Mark a session **compromised** (from active or revoked), setting
    /// `end_reason` and — if not ended yet — `ended_at = now`.  Returns
    /// `false` if the session is gone.
    async fn mark_compromised(
        &self,
        session_id: Uuid,
        reason: RevocationReason,
    ) -> Result<bool, AuthError>;

    /// End every active session of a user.  Returns the IDs ended.
    async fn end_all_for_user(
        &self,
        user_id: Uuid,
        status: SessionStatus,
        reason: RevocationReason,
    ) -> Result<Vec<Uuid>, AuthError>;

    /// Active sessions of a user that have not yet passed their idle or
    /// absolute expiry, oldest first.
    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<Session>, AuthError>;

    /// Delete sessions (and their generations) that ended, or passed their
    /// idle or absolute expiry, more than `retention` ago.  Returns the
    /// number deleted.
    async fn purge(&self, retention: Duration) -> Result<u64, AuthError>;
}
