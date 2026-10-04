//! Permission token encoding — the [`PermissionCodec`] port and its
//! built-in implementation, [`BitsetPermissionCodec`] (format v1, specified
//! in `docs/authorization.md`).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::authorization::model::{
    EffectiveGrants, EffectivePermissions, PermissionCatalog, PermissionKind, PermissionValue,
};
use crate::token::model::EncodedPermissions;

/// Encodes grants into a token and decodes them back against a catalog.
/// Decoding must fail closed: anything unknown or malformed is "not granted".
pub trait PermissionCodec: Send + Sync {
    fn encode(&self, grants: &EffectiveGrants) -> EncodedPermissions;
    fn decode(
        &self,
        encoded: &EncodedPermissions,
        catalog: &PermissionCatalog,
    ) -> EffectivePermissions;
}

/// Format v1: granted `bool` permissions and chosen options are bits of a
/// little-endian bitset (position `p` → byte `p / 8`, bit `p % 8`), trailing
/// zero bytes trimmed, base64url without padding; `text` values travel in a
/// position → value map.
#[derive(Debug, Default, Clone, Copy)]
pub struct BitsetPermissionCodec;

impl PermissionCodec for BitsetPermissionCodec {
    fn encode(&self, grants: &EffectiveGrants) -> EncodedPermissions {
        let mut bytes: Vec<u8> = Vec::new();
        let mut text = BTreeMap::new();
        for grant in &grants.grants {
            match &grant.text {
                Some(value) => {
                    text.insert(grant.position, value.clone());
                }
                None => {
                    let byte = (grant.position / 8) as usize;
                    if bytes.len() <= byte {
                        bytes.resize(byte + 1, 0);
                    }
                    bytes[byte] |= 1 << (grant.position % 8);
                }
            }
        }
        EncodedPermissions {
            catalog_version: grants.catalog_version,
            bits: URL_SAFE_NO_PAD.encode(&bytes),
            text,
        }
    }

    fn decode(
        &self,
        encoded: &EncodedPermissions,
        catalog: &PermissionCatalog,
    ) -> EffectivePermissions {
        // Tokens are signed, so malformed bits mean a bug: grant nothing.
        let bytes = URL_SAFE_NO_PAD.decode(&encoded.bits).unwrap_or_default();
        let bit = |position: u32| {
            bytes
                .get((position / 8) as usize)
                .is_some_and(|b| b & (1 << (position % 8)) != 0)
        };

        let mut values = BTreeMap::new();
        for permission in &catalog.permissions {
            let chosen = || {
                permission
                    .options
                    .iter()
                    .filter(|o| bit(o.position))
                    .map(|o| o.code.clone())
            };
            let value = match permission.kind {
                PermissionKind::Bool => permission
                    .position
                    .filter(|&p| bit(p))
                    .map(|_| PermissionValue::Allow),
                PermissionKind::Single => chosen().next().map(PermissionValue::Choice),
                PermissionKind::Multi => {
                    let options: Vec<String> = chosen().collect();
                    (!options.is_empty()).then_some(PermissionValue::Choices(options))
                }
                PermissionKind::Text { .. } => permission
                    .position
                    .and_then(|p| encoded.text.get(&p))
                    .map(|t| PermissionValue::Text(t.clone())),
            };
            if let Some(value) = value {
                values.insert(permission.code.clone(), value);
            }
        }
        EffectivePermissions::new(values, encoded.catalog_version > catalog.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::model::{Permission, PermissionGrant, PermissionOption};
    use uuid::Uuid;

    fn entry(
        code: &str,
        kind: PermissionKind,
        position: Option<u32>,
        options: &[(&str, u32)],
    ) -> Permission {
        Permission {
            id: Uuid::new_v4(),
            code: code.into(),
            kind,
            description: None,
            position,
            options: options
                .iter()
                .map(|(c, p)| PermissionOption {
                    id: Uuid::new_v4(),
                    code: (*c).into(),
                    position: *p,
                })
                .collect(),
            created_at: chrono::Utc::now(),
        }
    }

    /// reports.view (bool @0), reports.export (multi csv@1 pdf@2 xlsx@3),
    /// region (single eu@4 us@5), upload.max_mb (text @6), audit (bool @70).
    fn catalog() -> PermissionCatalog {
        PermissionCatalog {
            version: 70,
            permissions: vec![
                entry("reports.view", PermissionKind::Bool, Some(0), &[]),
                entry(
                    "reports.export",
                    PermissionKind::Multi,
                    None,
                    &[("csv", 1), ("pdf", 2), ("xlsx", 3)],
                ),
                entry(
                    "region",
                    PermissionKind::Single,
                    None,
                    &[("eu", 4), ("us", 5)],
                ),
                entry(
                    "upload.max_mb",
                    PermissionKind::Text { max_length: 8 },
                    Some(6),
                    &[],
                ),
                entry("audit", PermissionKind::Bool, Some(70), &[]),
            ],
        }
    }

    fn grants(positions: &[u32], text: &[(u32, &str)]) -> EffectiveGrants {
        EffectiveGrants {
            catalog_version: 70,
            grants: positions
                .iter()
                .map(|&position| PermissionGrant {
                    position,
                    text: None,
                })
                .chain(text.iter().map(|(p, t)| PermissionGrant {
                    position: *p,
                    text: Some((*t).into()),
                }))
                .collect(),
        }
    }

    #[test]
    fn round_trip() {
        let codec = BitsetPermissionCodec;
        let encoded = codec.encode(&grants(&[0, 1, 3, 5, 70], &[(6, "250")]));
        // bits 0,1,3,5 → 0b0010_1011 = 0x2B; bit 70 → byte 8, bit 6 = 0x40.
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&encoded.bits).unwrap(),
            vec![0x2B, 0, 0, 0, 0, 0, 0, 0, 0x40]
        );

        let p = codec.decode(&encoded, &catalog());
        assert!(p.allowed("reports.view"));
        assert_eq!(p.choices("reports.export"), ["csv", "xlsx"]);
        assert_eq!(p.choice("region"), Some("us"));
        assert_eq!(p.text("upload.max_mb"), Some("250"));
        assert!(p.allowed("audit"));
        assert!(!p.catalog_outdated);
    }

    #[test]
    fn empty_grants_encode_to_nothing() {
        let codec = BitsetPermissionCodec;
        let encoded = codec.encode(&grants(&[], &[]));
        assert_eq!(encoded.bits, "");
        assert!(encoded.text.is_empty());
        assert!(codec.decode(&encoded, &catalog()).values().is_empty());
    }

    #[test]
    fn unknown_positions_and_newer_catalogs_fail_closed() {
        let codec = BitsetPermissionCodec;
        let mut encoded = codec.encode(&grants(&[0, 99], &[(98, "x")]));
        encoded.catalog_version = 99;
        let p = codec.decode(&encoded, &catalog());
        assert_eq!(p.values().len(), 1, "only reports.view is known");
        assert!(p.catalog_outdated);

        encoded.bits = "%%%not-base64".into();
        assert!(!codec.decode(&encoded, &catalog()).allowed("reports.view"));
    }
}
