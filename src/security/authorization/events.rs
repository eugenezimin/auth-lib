//! The permission service's own outbound port for catalog changes.
//!
//! Authorization sits below `eventing`, so it cannot name the domain-event
//! enum.  Every event publisher implements [`CatalogEvents`] by wrapping
//! the call in the matching domain event, so hosts never implement it
//! directly.

use async_trait::async_trait;

/// Best effort and non-failing, like every event delivery.
#[async_trait]
pub trait CatalogEvents: Send + Sync {
    /// The permission catalog grew to `version`.
    async fn catalog_changed(&self, version: u64);
}
