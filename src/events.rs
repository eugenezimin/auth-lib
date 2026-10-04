//! Domain events — changes other auth-lib instances must learn about
//! immediately, because they affect tokens already in flight.
//!
//! Services publish through the [`EventPublisher`] port.  Standalone
//! deployments use [`NoopPublisher`]; with the `cluster` feature the
//! cluster pushes every event to all peers.

use async_trait::async_trait;

use crate::token::model::{Revocation, VerifyingKeyRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "data", rename_all = "snake_case")
)]
pub enum DomainEvent {
    /// A new (pending) revocation.
    Revoked(Revocation),
    /// A revocation was enforced (a covered token was used and blocked).
    RevocationEnforced(Revocation),
    /// A verifying key to accept from now on.
    VerifyingKeyPublished(VerifyingKeyRecord),
    /// Reject every token signed with this key id.
    SigningKeyRevoked { kid: String },
    /// The permission catalog grew to `version`.
    CatalogChanged { version: u64 },
}

/// Delivers domain events to the other instances.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Best effort and non-failing: delivery problems are retried or
    /// repaired by the publisher, never surfaced to the caller.
    async fn publish(&self, event: DomainEvent);
}

/// Single-instance deployments: nothing to tell anyone.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPublisher;

#[async_trait]
impl EventPublisher for NoopPublisher {
    async fn publish(&self, _event: DomainEvent) {}
}
