/// Token blocklist interface.
///
/// Contract for checking and registering revoked JWT IDs (`jti`).
/// The in-process implementation lives in [`crate::auth::blocklist`];
/// a Redis-backed implementation can be dropped in later without changing
/// any call sites.
use async_trait::async_trait;

use crate::utils::errors::AuthError;

#[async_trait]
pub trait TokenBlocklist: Send + Sync {
    /// Returns `true` if the given `jti` has been revoked.
    async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError>;

    /// Mark a `jti` as revoked until `expires_at`.
    /// The implementation is free to ignore entries past their TTL.
    async fn revoke(
        &self,
        jti: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;

    /// Revoke all `jti`s in the slice in a single operation.
    /// Used by logout-all to drain a user's sessions atomically.
    async fn revoke_many(
        &self,
        jtis: &[(&str, chrono::DateTime<chrono::Utc>)],
    ) -> Result<(), AuthError>;
}
