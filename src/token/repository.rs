//! Token-context ports: the persisted side of the denylist and the
//! published verifying keys.  auth-lib ships **no implementation**.
//!
//! Neither is read on token verification.  They are written when something
//! changes (a revocation, its enforcement, a key event) and read once at
//! startup to seed the in-memory [`Denylist`](crate::token::Denylist) and
//! [`KeyRing`](crate::token::KeyRing).  Timestamps come from the store.

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::token::model::{NewRevocation, NewVerifyingKey, Revocation, VerifyingKeyRecord};

#[async_trait]
pub trait RevocationRepository: Send + Sync {
    /// Store a **pending** revocation with `revoked_at = now` and
    /// `expires_at = now + ttl`, and return it as stored.
    async fn insert(&self, revocation: &NewRevocation) -> Result<Revocation, AuthError>;

    /// Compare-and-swap `pending → enforced` (`enforced_at = now`,
    /// `enforced_by = by`).  `None` if it was already enforced (or is gone):
    /// exactly one instance wins.
    async fn mark_enforced(&self, id: Uuid, by: Uuid) -> Result<Option<Revocation>, AuthError>;

    /// All revocations whose `expires_at` is still in the future.
    async fn list_active(&self) -> Result<Vec<Revocation>, AuthError>;

    /// Delete revocations whose `expires_at` has passed.  Returns the
    /// number removed.
    async fn purge_expired(&self) -> Result<u64, AuthError>;
}

#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Store a verifying key (idempotent per `kid`; a revoked key stays
    /// revoked) and return it as stored.
    async fn publish(&self, key: &NewVerifyingKey) -> Result<VerifyingKeyRecord, AuthError>;

    /// Mark `kid` revoked.  `None` if the key is unknown.
    async fn revoke(&self, kid: &str) -> Result<Option<VerifyingKeyRecord>, AuthError>;

    /// Every stored key, active and revoked.
    async fn list(&self) -> Result<Vec<VerifyingKeyRecord>, AuthError>;
}
