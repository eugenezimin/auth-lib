//! Generating z-auth-mfa's keys.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use z_auth::AuthError;

use crate::constants::{ENCRYPTION_KEY_LEN, MIN_HASH_KEY_LEN};
use crate::crypto::codes::random_bytes;

/// Freshly generated keys, base64-encoded for `AUTH_MFA_ENCRYPTION_KEY`
/// and `AUTH_MFA_HASH_KEY`.
pub struct GeneratedMfaKeys {
    pub encryption_key: String,
    pub hash_key: String,
}

/// A new encryption key and hash key.
pub fn generate_keys() -> Result<GeneratedMfaKeys, AuthError> {
    Ok(GeneratedMfaKeys {
        encryption_key: BASE64.encode(random_bytes(ENCRYPTION_KEY_LEN)?),
        hash_key: BASE64.encode(random_bytes(MIN_HASH_KEY_LEN)?),
    })
}

impl std::fmt::Debug for GeneratedMfaKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GeneratedMfaKeys(<redacted>)")
    }
}
