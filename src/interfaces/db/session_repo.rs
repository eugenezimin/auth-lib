/// Session repository interface.
///
/// Persistence contract for the `sessions` table.
/// All implementations live in [`crate::storage::postgres::session_repo`].
use async_trait::async_trait;

use crate::model::session::{NewSession, Session};
use crate::utils::errors::AuthError;

#[async_trait]
pub(crate) trait SessionRepo: Send + Sync {
    /// Insert a new session row and return the fully hydrated [`Session`].
    async fn create(&self, new_session: NewSession) -> Result<Session, AuthError>;

    /// Fetch a session by its access token.
    async fn find_by_access_token(&self, token: &str) -> Result<Option<Session>, AuthError>;

    /// Fetch a session by its refresh token.
    async fn find_by_refresh_token(&self, token: &str) -> Result<Option<Session>, AuthError>;

    /// Delete a single session by its UUID (logout).
    async fn delete(&self, session_id: uuid::Uuid) -> Result<bool, AuthError>;

    /// Delete all sessions for a user (logout everywhere).
    async fn delete_all_for_user(&self, user_id: uuid::Uuid) -> Result<u64, AuthError>;

    /// Delete all sessions whose `refresh_expires_at` is in the past.
    /// Called before enforcing the per-user session cap.
    async fn delete_expired_for_user(&self, user_id: uuid::Uuid) -> Result<u64, AuthError>;

    /// Count active (non-expired) sessions for a user.
    async fn count_active_for_user(&self, user_id: uuid::Uuid) -> Result<i64, AuthError>;
}
