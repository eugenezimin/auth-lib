//! Domain events — changes other z-auth instances must learn about
//! immediately, because they affect tokens already in flight.
//!
//! Services publish through the [`EventPublisher`] port.  This is how an
//! extension subscribes to denylist, key and catalog changes: it registers
//! a publisher (see [`ConfigureContext::subscribe`]) and every event reaches
//! it — a cluster pushes them to its peers.  With no subscriber the
//! [`NoopPublisher`] drops them; with several, a [`FanoutPublisher`]
//! delivers each to all.  Token and permission services announce through
//! their own ports, [`TokenEvents`] and [`CatalogEvents`], which every
//! publisher implements.
//!
//! [`ConfigureContext::subscribe`]: crate::controller::extension::ConfigureContext::subscribe

use std::sync::Arc;

use async_trait::async_trait;

use crate::security::authorization::CatalogEvents;
use crate::security::token::TokenEvents;
use crate::security::token::model::{Revocation, VerifyingKeyRecord};

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
pub trait EventPublisher: TokenEvents + CatalogEvents + Send + Sync {
    /// Best effort and non-failing: delivery problems are retried or
    /// repaired by the publisher, never surfaced to the caller.
    async fn publish(&self, event: DomainEvent);
}

#[async_trait]
impl<P: EventPublisher + ?Sized> TokenEvents for P {
    async fn revoked(&self, revocation: Revocation) {
        self.publish(DomainEvent::Revoked(revocation)).await;
    }
    async fn revocation_enforced(&self, revocation: Revocation) {
        self.publish(DomainEvent::RevocationEnforced(revocation))
            .await;
    }
    async fn verifying_key_published(&self, key: VerifyingKeyRecord) {
        self.publish(DomainEvent::VerifyingKeyPublished(key)).await;
    }
    async fn signing_key_revoked(&self, kid: String) {
        self.publish(DomainEvent::SigningKeyRevoked { kid }).await;
    }
}

#[async_trait]
impl<P: EventPublisher + ?Sized> CatalogEvents for P {
    async fn catalog_changed(&self, version: u64) {
        self.publish(DomainEvent::CatalogChanged { version }).await;
    }
}

/// Single-instance deployments: nothing to tell anyone.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPublisher;

#[async_trait]
impl EventPublisher for NoopPublisher {
    async fn publish(&self, _event: DomainEvent) {}
}

/// Delivers every event to each subscriber, in registration order.
pub struct FanoutPublisher(Vec<Arc<dyn EventPublisher>>);

impl FanoutPublisher {
    pub fn new(subscribers: Vec<Arc<dyn EventPublisher>>) -> Self {
        Self(subscribers)
    }
}

#[async_trait]
impl EventPublisher for FanoutPublisher {
    async fn publish(&self, event: DomainEvent) {
        for subscriber in &self.0 {
            subscriber.publish(event.clone()).await;
        }
    }
}
