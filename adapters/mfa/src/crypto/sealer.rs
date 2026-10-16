//! Encryption at rest of the secrets z-auth-mfa must read back: TOTP shared
//! secrets and email / SMS destinations.
//!
//! [`SecretSealer`] is a port, so a host can seal with a KMS instead.  The
//! built-in [`XChaChaSealer`] (feature `aead`) uses XChaCha20-Poly1305 with
//! a random 192-bit nonce per value:
//!
//! `version (1) ‖ key id (8) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`
//!
//! The key id (first bytes of the key's SHA-256) picks the opening key, so
//! keys can be rotated: seal with the new one, keep the old ones for
//! opening.  The associated data binds each value to its row (user and
//! factor id), so a sealed value copied to another row does not open.

use z_auth::AuthError;

/// Seals and opens secrets stored by z-auth-mfa.
pub trait SecretSealer: Send + Sync {
    /// Encrypt `plaintext`, authenticating `aad` with it.
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AuthError>;
    /// Decrypt a value from [`seal`](Self::seal) with the same `aad`.
    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, AuthError>;
}

#[cfg(feature = "aead")]
pub use xchacha::XChaChaSealer;

#[cfg(feature = "aead")]
mod xchacha {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    use sha2::{Digest, Sha256};
    use z_auth::AuthError;

    use super::SecretSealer;
    use crate::constants::{SEALED_FORMAT_VERSION, SEALED_KEY_ID_LEN};
    use crate::crypto::codes::random_bytes;

    const NONCE_LEN: usize = 24;
    const HEADER_LEN: usize = 1 + SEALED_KEY_ID_LEN + NONCE_LEN;

    type KeyId = [u8; SEALED_KEY_ID_LEN];

    fn key_id(key: &[u8; 32]) -> KeyId {
        Sha256::digest(key)[..SEALED_KEY_ID_LEN]
            .try_into()
            .expect("digest is longer than the key id")
    }

    /// XChaCha20-Poly1305 with key rotation.
    pub struct XChaChaSealer {
        current: (KeyId, XChaCha20Poly1305),
        previous: Vec<(KeyId, XChaCha20Poly1305)>,
    }

    impl XChaChaSealer {
        /// Seal with `current`; open with it or any of `previous`.
        pub fn new(current: &[u8; 32], previous: &[[u8; 32]]) -> Self {
            let cipher = |k: &[u8; 32]| (key_id(k), XChaCha20Poly1305::new(&(*k).into()));
            Self {
                current: cipher(current),
                previous: previous.iter().map(cipher).collect(),
            }
        }

        fn cipher_for(&self, id: &[u8]) -> Option<&XChaCha20Poly1305> {
            std::iter::once(&self.current)
                .chain(&self.previous)
                .find(|(kid, _)| kid.as_slice() == id)
                .map(|(_, c)| c)
        }
    }

    impl SecretSealer for XChaChaSealer {
        fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AuthError> {
            let nonce_bytes = random_bytes(NONCE_LEN)?;
            let nonce = XNonce::try_from(nonce_bytes.as_slice())
                .map_err(|_| AuthError::Internal("nonce length".into()))?;
            let ciphertext = self
                .current
                .1
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AuthError::Internal("sealing failed".into()))?;
            let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
            out.push(SEALED_FORMAT_VERSION);
            out.extend_from_slice(&self.current.0);
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }

        fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, AuthError> {
            if sealed.len() < HEADER_LEN || sealed[0] != SEALED_FORMAT_VERSION {
                return Err(AuthError::Internal("malformed sealed value".into()));
            }
            let id = &sealed[1..1 + SEALED_KEY_ID_LEN];
            let cipher = self.cipher_for(id).ok_or_else(|| {
                AuthError::Config(
                    "a stored second-factor secret was sealed with an unknown key; \
                     add it to AUTH_MFA_PREVIOUS_ENCRYPTION_KEYS"
                        .into(),
                )
            })?;
            let nonce = XNonce::try_from(&sealed[1 + SEALED_KEY_ID_LEN..HEADER_LEN])
                .map_err(|_| AuthError::Internal("nonce length".into()))?;
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &sealed[HEADER_LEN..],
                        aad,
                    },
                )
                .map_err(|_| AuthError::Internal("sealed value failed authentication".into()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const K1: [u8; 32] = [1; 32];
        const K2: [u8; 32] = [2; 32];

        #[test]
        fn round_trip_with_fresh_nonces() {
            let s = XChaChaSealer::new(&K1, &[]);
            let a = s.seal(b"secret", b"row-1").unwrap();
            let b = s.seal(b"secret", b"row-1").unwrap();
            assert_ne!(a, b, "random nonce per value");
            assert_eq!(s.open(&a, b"row-1").unwrap(), b"secret");
        }

        #[test]
        fn tampering_or_another_row_fails() {
            let s = XChaChaSealer::new(&K1, &[]);
            let mut sealed = s.seal(b"secret", b"row-1").unwrap();
            assert!(s.open(&sealed, b"row-2").is_err(), "bound to its row");
            let last = sealed.len() - 1;
            sealed[last] ^= 1;
            assert!(s.open(&sealed, b"row-1").is_err());
            assert!(s.open(&[1, 2, 3], b"row-1").is_err());
        }

        #[test]
        fn rotated_keys_still_open_old_values() {
            let old = XChaChaSealer::new(&K1, &[]);
            let sealed = old.seal(b"secret", b"row").unwrap();
            let rotated = XChaChaSealer::new(&K2, &[K1]);
            assert_eq!(rotated.open(&sealed, b"row").unwrap(), b"secret");
            let resealed = rotated.seal(b"secret", b"row").unwrap();
            assert!(matches!(
                old.open(&resealed, b"row"),
                Err(AuthError::Config(_))
            ));
            let forgotten = XChaChaSealer::new(&K2, &[]);
            assert!(matches!(
                forgotten.open(&sealed, b"row"),
                Err(AuthError::Config(_))
            ));
        }
    }
}
