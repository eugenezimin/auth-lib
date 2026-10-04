//! OS-backed randomness for session secrets and key generation.

use crate::error::AuthError;

/// `len` bytes from the operating system's CSPRNG.
pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, AuthError> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|e| AuthError::Internal(format!("OS RNG failure: {e}")))?;
    Ok(buf)
}
