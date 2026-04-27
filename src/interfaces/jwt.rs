/// JWT signing and verification interfaces.
///
/// Two traits, one per token type:
///
/// - [`AccessTokenService`]  — global secret, synchronous, zero external calls.
/// - [`RefreshTokenService`] — per-user secret, requires a secret lookup.
///
/// Implementations live in [`crate::auth::jwt`].
use async_trait::async_trait;

use crate::model::token::Claims;
use crate::utils::errors::AuthError;

// ── Access token ──────────────────────────────────────────────────────────────

/// Signs and verifies access tokens using the global secret from config.
///
/// All operations are synchronous and purely local — no DB, no cache, no I/O.
pub trait AccessTokenService: Send + Sync {
    /// Mint a signed access token for the given `user_id`.
    /// `jti` must be a freshly generated UUID string (caller's responsibility).
    fn mint(&self, user_id: uuid::Uuid, jti: &str) -> Result<String, AuthError>;

    /// Verify the token's signature and expiry, returning the decoded [`Claims`].
    ///
    /// Does **not** check the blocklist — the caller (`AuthService`) does that.
    fn verify(&self, token: &str) -> Result<Claims, AuthError>;
}

// ── Refresh token ─────────────────────────────────────────────────────────────

/// Signs and verifies refresh tokens using a per-user secret.
///
/// Verification requires the per-user secret, obtained from the DB or a cache.
/// Because that lookup is async, both methods are `async`.
#[async_trait]
pub trait RefreshTokenService: Send + Sync {
    /// Mint a signed refresh token for the given `user_id`, signing with `user_secret`.
    /// `jti` must be a freshly generated UUID string (caller's responsibility).
    async fn mint(
        &self,
        user_id: uuid::Uuid,
        jti: &str,
        user_secret: &str,
    ) -> Result<String, AuthError>;

    /// Verify the token's signature and expiry using `user_secret`.
    ///
    /// Does **not** check the blocklist — the caller does that.
    async fn verify(&self, token: &str, user_secret: &str) -> Result<Claims, AuthError>;
}
