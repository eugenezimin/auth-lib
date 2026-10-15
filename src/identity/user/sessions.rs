//! The user service's port for ending a user's sessions when the account
//! changes.
//!
//! Identity sits below `security`, so it cannot name the token revocation
//! service.  Every token revocation service implements [`AccountSessions`]
//! (mapping each [`AccountChange`] to its revocation reason), so hosts
//! never implement it directly.

use async_trait::async_trait;
use uuid::Uuid;

use crate::utils::error::AuthError;

/// Why every session of an account ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountChange {
    PasswordChanged,
    Disabled,
    Deleted,
}

#[async_trait]
pub trait AccountSessions: Send + Sync {
    /// End every active session of `user_id` and deny all of their tokens
    /// issued until now.  Returns the number of sessions ended.
    async fn end_sessions_for(
        &self,
        user_id: Uuid,
        change: AccountChange,
    ) -> Result<u64, AuthError>;
}
