//! Hook a refresh consults before rotating, installed by an extension: a
//! replicated deployment refuses when this instance is too far behind, and
//! fetches a session (or its user's account) that has not reached it yet.

use async_trait::async_trait;
use uuid::Uuid;

use crate::utils::error::AuthError;

#[async_trait]
pub trait RefreshGate: Send + Sync {
    /// Fail (e.g. [`AuthError::ReplicaStale`]) when this instance's state is
    /// too old to judge a refresh.
    async fn check_fresh(&self) -> Result<(), AuthError>;

    /// Fetch the session and its user's account from elsewhere.  Returns
    /// `true` if either arrived (or changed).
    async fn catch_up(&self, session_id: Uuid, user_id: Uuid) -> Result<bool, AuthError>;
}
