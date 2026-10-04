//! Password hashing interface.

use crate::error::AuthError;

/// Hashes and verifies passwords.
///
/// Methods are synchronous and CPU-bound; host applications on an async
/// runtime may wrap calls in their runtime's blocking-task facility if
/// hashing cost is a concern.
///
/// The built-in implementation is
/// [`Argon2Hasher`](crate::credentials::Argon2Hasher) (feature `argon2`).
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password.  The output must be self-describing
    /// (algorithm, parameters, salt) so it can be stored verbatim.
    fn hash(&self, plaintext: &str) -> Result<String, AuthError>;

    /// Verify a plaintext password against a stored hash.
    ///
    /// `Ok(false)` means "wrong password"; `Err` means the stored hash is
    /// malformed or verification failed for another reason.
    fn verify(&self, plaintext: &str, stored_hash: &str) -> Result<bool, AuthError>;
}
