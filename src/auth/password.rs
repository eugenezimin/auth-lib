/// Password hashing and verification.
///
/// Uses Argon2id (memory-hard, recommended for password storage) via the
/// `argon2` crate.  All logic is pure — no I/O, no async — so it can be
/// called from any context.
///
/// # Design
///
/// - [`hash_password`]   — called once during registration
/// - [`verify_password`] — called on every login attempt
///
/// Argon2id produces a self-describing string (e.g.
/// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`) that encodes the
/// algorithm, version, parameters, salt, and digest.  This string is stored
/// verbatim in `users.password_hash` and is all that's needed for future
/// verification — no separate salt column required.
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::utils::errors::AuthError;

// ── Public API ────────────────────────────────────────────────────────────────

/// Hash a plaintext password with Argon2id.
///
/// Generates a fresh random salt on every call, so two calls with the same
/// password produce different hashes — this is the expected behavior.
///
/// # Errors
///
/// Returns [`AuthError::HashingError`] if the underlying Argon2 library fails
/// (e.g. an internal RNG failure — extremely rare in practice).
pub fn hash_password(plaintext: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default(); // Argon2id with OWASP-recommended params

    argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AuthError::HashingError(e.to_string()))
}

/// Verify a plaintext password against a stored Argon2id hash.
///
/// Returns `Ok(true)` when the password matches, `Ok(false)` when it does not.
/// The distinction between "wrong password" (`Ok(false)`) and "hash is
/// malformed" (`Err`) lets callers decide how to handle each case.
///
/// # Errors
///
/// Returns [`AuthError::HashingError`] if `stored_hash` is not a valid
/// Argon2 PHC string (i.e. the value stored in the database is corrupt).
pub fn verify_password(plaintext: &str, stored_hash: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AuthError::HashingError(format!("malformed hash in database: {e}")))?;

    match Argon2::default().verify_password(plaintext.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AuthError::HashingError(e.to_string())),
    }
}
