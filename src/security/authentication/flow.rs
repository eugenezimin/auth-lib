//! Short-lived state of multi-step sign-ins: a sign-in waiting for the
//! local password, the method that started a login now waiting for a
//! second factor, and a protocol adapter's redirect state (OIDC `state`,
//! nonce and PKCE verifier).

use std::time::Duration;

use async_trait::async_trait;

use crate::utils::error::AuthError;

/// Single-use entries that expire.  Keys are built with [`flow_key`] and
/// never contain a token in the clear.
#[async_trait]
pub trait FlowStateRepository: Send + Sync {
    /// Store `value` under `key` for `ttl`, the expiry computed by the
    /// store.  Replaces an entry with the same key.
    async fn put(&self, key: &str, value: &str, ttl: Duration) -> Result<(), AuthError>;

    /// Remove and return the entry unless it has expired.  Atomic: of
    /// concurrent calls with one key at most one gets the value.
    async fn take(&self, key: &str) -> Result<Option<String>, AuthError>;

    /// Delete expired entries.  Returns the number deleted.
    async fn purge_expired(&self) -> Result<u64, AuthError>;
}

/// The store key of the entry of kind `kind` (`link`, `mfa`, `sso`, …)
/// that `secret` (a token handed to the client) opens: `kind:` plus the
/// secret's SHA-256, so a leaked store reveals no usable token.  Without
/// the `crypto` feature the secret itself is used.
pub fn flow_key(kind: &str, secret: &str) -> String {
    format!("{kind}:{}", digest(secret))
}

#[cfg(feature = "crypto")]
fn digest(secret: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(not(feature = "crypto"))]
fn digest(secret: &str) -> String {
    secret.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_namespaced_and_hide_the_secret() {
        let key = flow_key("link", "s3cret");
        assert!(key.starts_with("link:"));
        assert_ne!(flow_key("mfa", "s3cret"), key);
        #[cfg(feature = "crypto")]
        assert!(!key.contains("s3cret"));
    }
}
