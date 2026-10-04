//! [`KeyRing`] — the verifying keys this instance accepts, and the key ids
//! it must reject.  In memory; consulted by the token decoder on every
//! verification.  Seeded from configuration and the store at startup, then
//! updated by key events pushed from other instances.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::token::model::{KeyStatus, VerifyingKeyRecord};

#[derive(Debug, Default)]
pub struct KeyRing {
    keys: RwLock<HashMap<String, VerifyingKeyRecord>>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a key.  `Revoked` is terminal and wins over `Active`.
    /// Returns `true` if the ring changed.
    pub fn merge(&self, record: VerifyingKeyRecord) -> bool {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        match keys.get_mut(&record.kid) {
            Some(existing) => {
                let mut changed = false;
                if record.status > existing.status {
                    existing.status = record.status;
                    existing.revoked_at = record.revoked_at;
                    changed = true;
                }
                // A key seeded from configuration learns its stored metadata.
                if existing.published_by.is_none() && record.published_by.is_some() {
                    existing.published_by = record.published_by;
                    existing.created_at = record.created_at;
                    changed = true;
                }
                changed
            }
            None => {
                keys.insert(record.kid.clone(), record);
                true
            }
        }
    }

    /// Mark `kid` revoked (known or not).  Returns `true` if it changed.
    pub fn revoke(&self, kid: &str, at: chrono::DateTime<chrono::Utc>) -> bool {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        match keys.get_mut(kid) {
            Some(k) if k.status == KeyStatus::Revoked => false,
            Some(k) => {
                k.status = KeyStatus::Revoked;
                k.revoked_at = Some(at);
                true
            }
            None => {
                // Remember the revocation even before the key is known.
                keys.insert(
                    kid.to_owned(),
                    VerifyingKeyRecord {
                        kid: kid.to_owned(),
                        public_key: [0; 32],
                        status: KeyStatus::Revoked,
                        published_by: None,
                        created_at: at,
                        revoked_at: Some(at),
                    },
                );
                true
            }
        }
    }

    /// The public key for `kid`, unless unknown or revoked.
    pub fn active(&self, kid: &str) -> Option<[u8; 32]> {
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        keys.get(kid)
            .filter(|k| k.status == KeyStatus::Active)
            .map(|k| k.public_key)
    }

    pub fn is_revoked(&self, kid: &str) -> bool {
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        keys.get(kid)
            .is_some_and(|k| k.status == KeyStatus::Revoked)
    }

    /// Every key, sorted by kid.
    pub fn records(&self) -> Vec<VerifyingKeyRecord> {
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        let mut all: Vec<_> = keys.values().cloned().collect();
        all.sort_by(|a, b| a.kid.cmp(&b.kid));
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn key(kid: &str, status: KeyStatus) -> VerifyingKeyRecord {
        VerifyingKeyRecord {
            kid: kid.into(),
            public_key: [7; 32],
            status,
            published_by: None,
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn revoked_is_terminal() {
        let ring = KeyRing::new();
        assert!(ring.merge(key("a", KeyStatus::Active)));
        assert_eq!(ring.active("a"), Some([7; 32]));
        assert!(ring.revoke("a", Utc::now()));
        assert!(ring.active("a").is_none());
        assert!(!ring.merge(key("a", KeyStatus::Active)), "cannot un-revoke");
        assert!(ring.is_revoked("a"));
        // A revocation that arrives before its key still sticks.
        assert!(ring.revoke("b", Utc::now()));
        assert!(!ring.merge(key("b", KeyStatus::Active)));
        assert!(ring.active("b").is_none());
    }
}
