//! Token revocation service interface.
//!
//! Backs the revocation API endpoint ([`crate::api::handlers::revoke`]) and
//! is used by the authentication flows (logout, eviction, compromise).
//! Revoking any token ends its **whole session**: the session is marked in
//! storage, a **pending** revocation is persisted, the local denylist is
//! updated immediately, and the revocation is pushed to every other
//! instance.  When a covered token is later presented anywhere, that
//! instance blocks it and enforces the revocation (see
//! [`enforce_pending`](TokenRevocationService::enforce_pending)).

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::token::model::{RevocationReason, RevokeTarget};

#[async_trait]
pub trait TokenRevocationService: Send + Sync {
    /// Revoke one target.  Returns the number of sessions ended.
    async fn revoke(
        &self,
        target: RevokeTarget,
        reason: RevocationReason,
    ) -> Result<u64, AuthError>;

    /// Revoke many targets.  Targets that are not valid tokens are skipped;
    /// storage errors abort.  Returns the number of sessions ended.
    async fn revoke_many(
        &self,
        targets: Vec<RevokeTarget>,
        reason: RevocationReason,
    ) -> Result<u64, AuthError>;

    /// End one session.  Returns `true` if it was active.
    async fn end_session(
        &self,
        session_id: Uuid,
        reason: RevocationReason,
    ) -> Result<bool, AuthError>;

    /// End every active session of a user and deny all of their tokens
    /// issued until now.  Returns the number of sessions ended.
    async fn end_all_for_user(
        &self,
        user_id: Uuid,
        reason: RevocationReason,
    ) -> Result<u64, AuthError>;

    /// Delete persisted revocations that have expired.
    async fn purge_expired(&self) -> Result<u64, AuthError>;

    /// Startup: load the active revocations into the in-memory denylist.
    /// Returns how many were loaded.
    async fn load(&self) -> Result<usize, AuthError>;

    /// Enforce the revocations whose tokens were presented since the last
    /// call: mark each revocation `enforced` (one instance wins), mark the
    /// presenting session `compromised`, and push the update.  Returns how
    /// many this instance enforced.  Called from `AuthLib::tick`.
    async fn enforce_pending(&self) -> Result<usize, AuthError>;
}
