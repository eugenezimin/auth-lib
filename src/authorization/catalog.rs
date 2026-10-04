//! [`CatalogCache`] — the in-memory permission catalog every decoder reads.
//!
//! Pure memory, like the denylist: filled at startup
//! ([`PermissionService::reload_catalog`](crate::authorization::PermissionService::reload_catalog)),
//! after catalog changes made through this instance, and during a login /
//! refresh that sees a newer catalog version.  Never touched by verification.

use std::sync::{Arc, RwLock};

use crate::authorization::model::PermissionCatalog;

#[derive(Debug, Default)]
pub struct CatalogCache {
    catalog: RwLock<Arc<PermissionCatalog>>,
}

impl CatalogCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current catalog (cheap: an `Arc` clone).
    pub fn get(&self) -> Arc<PermissionCatalog> {
        self.catalog
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn version(&self) -> u64 {
        self.get().version
    }

    /// Install a freshly loaded catalog.  Unconditional: a reload after a
    /// deletion may legitimately carry a lower version.
    pub fn replace(&self, catalog: PermissionCatalog) -> Arc<PermissionCatalog> {
        let catalog = Arc::new(catalog);
        *self.catalog.write().unwrap_or_else(|e| e.into_inner()) = catalog.clone();
        catalog
    }
}
