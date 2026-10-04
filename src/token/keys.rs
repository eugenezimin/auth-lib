//! Key generation helpers — feature `crypto`.
//!
//! See `examples/keygen.rs` for a ready-to-paste `.env` block.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;

use crate::constants::{ED25519_KEY_LEN, MIN_REFRESH_SECRET_LEN};
use crate::error::AuthError;
use crate::random::random_bytes;

/// A freshly generated Ed25519 key pair, base64-encoded.
pub struct GeneratedKeyPair {
    /// Goes to `AUTH_JWT_SIGNING_KEY` on the auth service only.
    pub signing_key: String,
    /// Goes to `AUTH_JWT_VERIFYING_KEYS` on every service.
    pub verifying_key: String,
}

pub fn generate_signing_key() -> Result<GeneratedKeyPair, AuthError> {
    let seed: [u8; ED25519_KEY_LEN] = random_bytes(ED25519_KEY_LEN)?
        .try_into()
        .expect("random_bytes returns the requested length");
    let signing = SigningKey::from_bytes(&seed);
    Ok(GeneratedKeyPair {
        signing_key: BASE64.encode(seed),
        verifying_key: BASE64.encode(signing.verifying_key().to_bytes()),
    })
}

/// A random base64 secret suitable for `AUTH_REFRESH_SECRET`.
pub fn generate_refresh_secret() -> Result<String, AuthError> {
    Ok(BASE64.encode(random_bytes(MIN_REFRESH_SECRET_LEN)?))
}
