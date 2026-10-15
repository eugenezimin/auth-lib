//! The token services' own outbound port for changes other instances must
//! learn about immediately.
//!
//! Token sits below `eventing`: the domain-event enum carries token records,
//! so token cannot name it.  Every event publisher implements
//! [`TokenEvents`] by wrapping each call in the matching domain event, so
//! hosts never implement it directly.

use async_trait::async_trait;

use crate::security::token::model::{Revocation, VerifyingKeyRecord};

/// Best effort and non-failing, like every event delivery.
#[async_trait]
pub trait TokenEvents: Send + Sync {
    /// A new (pending) revocation.
    async fn revoked(&self, revocation: Revocation);
    /// A revocation was enforced (a covered token was used and blocked).
    async fn revocation_enforced(&self, revocation: Revocation);
    /// A verifying key to accept from now on.
    async fn verifying_key_published(&self, key: VerifyingKeyRecord);
    /// Reject every token signed with this key id.
    async fn signing_key_revoked(&self, kid: String);
}
