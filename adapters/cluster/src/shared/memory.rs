//! The state every instance replicates in memory — denylist, key ring and
//! catalog version — with its snapshot, digest and merge rules.  Shared by
//! both cluster modes.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::shared::model::{ClusterSnapshot, SyncDigest};
use z_auth::eventing::DomainEvent;
use z_auth::security::authorization::catalog::CatalogCache;
use z_auth::security::authorization::service::PermissionService;
use z_auth::security::token::denylist::Denylist;
use z_auth::security::token::keyring::KeyRing;
use z_auth::utils::clock::Clock;

pub(crate) struct ReplicatedMemory {
    pub denylist: Arc<Denylist>,
    pub keyring: Arc<KeyRing>,
    pub catalog: Arc<CatalogCache>,
    pub permissions: Arc<dyn PermissionService>,
    pub clock: Arc<dyn Clock>,
}

impl ReplicatedMemory {
    pub fn snapshot(&self) -> ClusterSnapshot {
        ClusterSnapshot {
            revocations: self.denylist.entries(self.clock.now()),
            keys: self.keyring.records(),
            catalog_version: self.catalog.version(),
        }
    }

    /// Order-independent fingerprints (entries are already sorted).
    pub fn digest(&self) -> SyncDigest {
        let fingerprint = |lines: Vec<String>| {
            let mut hash = Sha256::new();
            for line in lines {
                hash.update(line.as_bytes());
                hash.update(b"\n");
            }
            hash.finalize()[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let snapshot = self.snapshot();
        SyncDigest {
            revocations: fingerprint(
                snapshot
                    .revocations
                    .iter()
                    .map(|r| format!("{}:{:?}", r.id, r.status))
                    .collect(),
            ),
            keys: fingerprint(
                snapshot
                    .keys
                    .iter()
                    .map(|k| format!("{}:{:?}", k.kid, k.status))
                    .collect(),
            ),
            catalog_version: snapshot.catalog_version,
        }
    }

    pub async fn catalog_reached(&self, version: u64) {
        if version > self.catalog.version() {
            // A database read, but only when another instance changed the
            // catalog.  Disabled modes simply have nothing to reload.
            let _ = self.permissions.reload_catalog().await;
        }
    }

    pub async fn apply_event(&self, event: DomainEvent) {
        match event {
            DomainEvent::Revoked(r) | DomainEvent::RevocationEnforced(r) => {
                self.denylist.apply(&r);
            }
            DomainEvent::VerifyingKeyPublished(key) => {
                self.keyring.merge(key);
            }
            DomainEvent::SigningKeyRevoked { kid } => {
                self.keyring.revoke(&kid, self.clock.now());
            }
            DomainEvent::CatalogChanged { version } => self.catalog_reached(version).await,
        }
    }

    pub async fn merge(&self, snapshot: ClusterSnapshot) {
        for r in &snapshot.revocations {
            self.denylist.apply(r);
        }
        for k in snapshot.keys {
            self.keyring.merge(k);
        }
        self.catalog_reached(snapshot.catalog_version).await;
    }
}
