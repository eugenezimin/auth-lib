//! Verifying-key distribution and signing-key revocation.
//!
//! [`KeyService`] persists key events, applies them to the in-memory
//! [`KeyRing`] (which the decoder reads on every verification), and pushes
//! them to every other instance.  Only **public** keys are stored or sent.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::clock::Clock;
use crate::error::AuthError;
use crate::events::{DomainEvent, EventPublisher};
use crate::token::jwt::key_id;
use crate::token::keyring::KeyRing;
use crate::token::model::{NewVerifyingKey, VerifyingKeyRecord};
use crate::token::repository::KeyRepository;

#[async_trait]
pub trait KeyService: Send + Sync {
    /// Accept tokens signed by the matching private key on every instance.
    /// Idempotent; a revoked key stays revoked.
    async fn publish_verifying_key(
        &self,
        public_key: [u8; 32],
    ) -> Result<VerifyingKeyRecord, AuthError>;

    /// Reject, everywhere and immediately, every token signed with `kid`.
    /// Returns `false` if the key id is unknown to the store (it is still
    /// revoked in memory and pushed).
    async fn revoke_signing_key(&self, kid: &str) -> Result<bool, AuthError>;

    /// Keys this instance knows (active and revoked).  No I/O.
    fn keys(&self) -> Vec<VerifyingKeyRecord>;

    /// Startup: load the stored keys into the key ring.
    async fn load(&self) -> Result<usize, AuthError>;
}

/// Default [`KeyService`].
pub struct KeyServiceImpl {
    repo: Arc<dyn KeyRepository>,
    ring: Arc<KeyRing>,
    events: Arc<dyn EventPublisher>,
    clock: Arc<dyn Clock>,
    node_id: Uuid,
}

impl KeyServiceImpl {
    pub fn new(
        repo: Arc<dyn KeyRepository>,
        ring: Arc<KeyRing>,
        events: Arc<dyn EventPublisher>,
        clock: Arc<dyn Clock>,
        node_id: Uuid,
    ) -> Self {
        Self {
            repo,
            ring,
            events,
            clock,
            node_id,
        }
    }
}

#[async_trait]
impl KeyService for KeyServiceImpl {
    async fn publish_verifying_key(
        &self,
        public_key: [u8; 32],
    ) -> Result<VerifyingKeyRecord, AuthError> {
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|e| AuthError::InvalidToken(format!("invalid verifying key: {e}")))?;
        let stored = self
            .repo
            .publish(&NewVerifyingKey {
                kid: key_id(&public_key),
                public_key,
                published_by: self.node_id,
            })
            .await?;
        self.ring.merge(stored.clone());
        self.events
            .publish(DomainEvent::VerifyingKeyPublished(stored.clone()))
            .await;
        Ok(stored)
    }

    async fn revoke_signing_key(&self, kid: &str) -> Result<bool, AuthError> {
        let stored = self.repo.revoke(kid).await?;
        let at = stored
            .as_ref()
            .and_then(|k| k.revoked_at)
            .unwrap_or_else(|| self.clock.now());
        self.ring.revoke(kid, at);
        self.events
            .publish(DomainEvent::SigningKeyRevoked { kid: kid.into() })
            .await;
        Ok(stored.is_some())
    }

    fn keys(&self) -> Vec<VerifyingKeyRecord> {
        self.ring.records()
    }

    async fn load(&self) -> Result<usize, AuthError> {
        let stored = self.repo.list().await?;
        Ok(stored
            .into_iter()
            .filter(|k| self.ring.merge(k.clone()))
            .count())
    }
}
