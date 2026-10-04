//! Token encoding / decoding interfaces.
//!
//! - [`AccessTokenIssuer`]  — mints access tokens.  Only the auth service holds
//!   the signing key.
//! - [`AccessTokenDecoder`] — verifies access tokens.  Every service holds the
//!   public verifying key(s).
//! - [`RefreshTokenCodec`]  — issues and checks opaque refresh tokens.
//!
//! All codecs are synchronous and purely local.  Built-in implementations
//! (feature `crypto`): `token::jwt::Ed25519Issuer`, `token::jwt::Ed25519Decoder`
//! and `token::refresh::HmacRefreshCodec`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::AuthError;
use crate::token::model::{Claims, ExpiryCheck, RefreshToken};

/// Mints signed access tokens.
///
/// Minting must be deterministic for the same claims so the refresh flow
/// can hand out the current pair again during the grace window.
pub trait AccessTokenIssuer: Send + Sync {
    fn mint(&self, claims: &Claims) -> Result<String, AuthError>;

    /// Key id (`kid`) of the signing key, if the format has one — lets the
    /// service refuse to mint with a key the cluster has revoked.
    fn key_id(&self) -> Option<&str> {
        None
    }
}

/// Verifies access tokens.
pub trait AccessTokenDecoder: Send + Sync {
    /// Verify the signature and issuer (and `exp` when `expiry` is
    /// [`ExpiryCheck::Enforce`]), returning the claims.
    ///
    /// Does **not** consult the denylist — see
    /// [`TokenVerifier`](crate::token::TokenVerifier).
    fn decode(
        &self,
        token: &str,
        now: DateTime<Utc>,
        expiry: ExpiryCheck,
    ) -> Result<Claims, AuthError>;
}

/// Issues and checks refresh tokens bound to a session generation.
pub trait RefreshTokenCodec: Send + Sync {
    /// Build the refresh token for `generation` of `session_id`.
    /// Must be deterministic for the same inputs.
    fn issue(
        &self,
        session_id: Uuid,
        generation: u32,
        session_secret: &[u8],
    ) -> Result<String, AuthError>;

    /// Parse the token's structure without verifying it.
    fn parse(&self, token: &str) -> Result<RefreshToken, AuthError>;

    /// Verify the token's MAC against the session's secret (constant time).
    fn verify(&self, token: &RefreshToken, session_secret: &[u8]) -> bool;
}
