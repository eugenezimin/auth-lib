//! Argon2id implementation of [`PasswordHasher`].
//!
//! Argon2id (memory-hard, recommended for password storage) produces a
//! self-describing string (e.g. `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`)
//! that encodes the algorithm, version, parameters, salt, and digest — no
//! separate salt column is required.

use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};

use crate::credentials::hasher::PasswordHasher;
use crate::error::AuthError;

/// Argon2id with the crate's OWASP-recommended default parameters.
#[derive(Debug, Default, Clone, Copy)]
pub struct Argon2Hasher;

impl PasswordHasher for Argon2Hasher {
    /// Generates a fresh random salt on every call, so two calls with the same
    /// password produce different hashes.
    fn hash(&self, plaintext: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);

        Argon2::default()
            .hash_password(plaintext.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| AuthError::HashingError(e.to_string()))
    }

    fn verify(&self, plaintext: &str, stored_hash: &str) -> Result<bool, AuthError> {
        let parsed = PasswordHash::new(stored_hash)
            .map_err(|e| AuthError::HashingError(format!("malformed stored hash: {e}")))?;

        match Argon2::default().verify_password(plaintext.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::HashingError(e.to_string())),
        }
    }
}
