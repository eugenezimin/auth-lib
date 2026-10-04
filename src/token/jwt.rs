//! Minimal EdDSA (Ed25519) JWT implementation — feature `crypto`.
//!
//! Deliberately narrow: exactly one algorithm with a fixed header.  Any
//! token whose header `alg` is not `EdDSA` (including `none` and `HS256`)
//! is rejected before signature verification.  The `kid` header selects the
//! verifying key, so several keys can be accepted during a key rotation.
//!
//! Format: `base64url(header) . base64url(payload) . base64url(signature)`,
//! unpadded, signature over the first two segments.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::JwtConfig;
use crate::constants::{
    FIELD_JWT_SIGNING_KEY, FIELD_JWT_VERIFYING_KEYS, JWT_ALG, JWT_KID_LEN, JWT_TYP,
};
use crate::error::AuthError;
use std::sync::Arc;

use crate::token::codec::{AccessTokenDecoder, AccessTokenIssuer};
use crate::token::keyring::KeyRing;
use crate::token::model::{
    AuthzClaims, Claims, EncodedPermissions, ExpiryCheck, KeyStatus, VerifyingKeyRecord,
};

// ── Wire structures ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    sub: String,
    sid: String,
    jti: String,
    #[serde(rename = "gen")]
    generation: u32,
    iss: String,
    iat: i64,
    exp: i64,
    /// Role codes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rol: Vec<String>,
    /// Encoded permissions; omitted when nothing is granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prm: Option<WirePermissions>,
    /// Permission catalog version; present whenever permissions are in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pv: Option<u64>,
}

#[derive(Serialize, Deserialize, Default)]
struct WirePermissions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    b: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    t: BTreeMap<u32, String>,
}

/// `Claims::authz` → `rol` / `prm` / `pv`.
fn authz_to_wire(
    authz: Option<&AuthzClaims>,
) -> (Vec<String>, Option<WirePermissions>, Option<u64>) {
    let Some(authz) = authz else {
        return (Vec::new(), None, None);
    };
    let (prm, pv) = match &authz.permissions {
        None => (None, None),
        Some(p) => {
            let prm = (!p.bits.is_empty() || !p.text.is_empty()).then(|| WirePermissions {
                b: p.bits.clone(),
                t: p.text.clone(),
            });
            (prm, Some(p.catalog_version))
        }
    };
    (authz.roles.clone(), prm, pv)
}

/// `rol` / `prm` / `pv` → `Claims::authz`.
fn authz_from_wire(
    rol: Vec<String>,
    prm: Option<WirePermissions>,
    pv: Option<u64>,
) -> Option<AuthzClaims> {
    let permissions = pv.map(|catalog_version| {
        let prm = prm.unwrap_or_default();
        EncodedPermissions {
            catalog_version,
            bits: prm.b,
            text: prm.t,
        }
    });
    (!rol.is_empty() || permissions.is_some()).then_some(AuthzClaims {
        roles: rol,
        permissions,
    })
}

/// `kid` = hex of the first bytes of SHA-256(verifying key).
pub fn key_id(verifying_key: &[u8; 32]) -> String {
    Sha256::digest(verifying_key)[..JWT_KID_LEN]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn invalid(reason: &str) -> AuthError {
    AuthError::InvalidToken(reason.to_string())
}

// ── Issuer ────────────────────────────────────────────────────────────────────

/// Signs access tokens with an Ed25519 key.  Auth service only.
pub struct Ed25519Issuer {
    signing_key: SigningKey,
    kid: String,
    /// Pre-encoded header segment (constant for a given key).
    header_segment: String,
}

impl Ed25519Issuer {
    pub fn new(signing_seed: &[u8; 32]) -> Result<Self, AuthError> {
        let signing_key = SigningKey::from_bytes(signing_seed);
        let kid = key_id(&signing_key.verifying_key().to_bytes());
        let header = Header {
            alg: JWT_ALG.into(),
            typ: Some(JWT_TYP.into()),
            kid: Some(kid.clone()),
        };
        let header_json =
            serde_json::to_vec(&header).map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Self {
            signing_key,
            kid,
            header_segment: B64URL.encode(header_json),
        })
    }

    /// Build from `JwtConfig::signing_key`.
    pub fn from_config(config: &JwtConfig) -> Result<Self, AuthError> {
        let seed = config
            .signing_key
            .as_ref()
            .ok_or_else(|| AuthError::Config(format!("missing {FIELD_JWT_SIGNING_KEY}")))?;
        Self::new(seed)
    }

    /// The verifying key matching this signing key.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl AccessTokenIssuer for Ed25519Issuer {
    fn key_id(&self) -> Option<&str> {
        Some(&self.kid)
    }

    fn mint(&self, claims: &Claims) -> Result<String, AuthError> {
        let (rol, prm, pv) = authz_to_wire(claims.authz.as_ref());
        let payload = Payload {
            sub: claims.sub.to_string(),
            sid: claims.sid.to_string(),
            jti: claims.jti.to_string(),
            generation: claims.generation,
            iss: claims.iss.clone(),
            iat: claims.iat,
            exp: claims.exp,
            rol,
            prm,
            pv,
        };
        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| AuthError::TokenCreationError(e.to_string()))?;

        let signing_input = format!("{}.{}", self.header_segment, B64URL.encode(payload_json));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            B64URL.encode(signature.to_bytes())
        ))
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Verifies Ed25519-signed access tokens.  Every service.
///
/// Keys come from a shared [`KeyRing`], so verifying keys published by
/// other instances are accepted, and revoked key ids rejected, without a
/// restart.
pub struct Ed25519Decoder {
    keys: Arc<KeyRing>,
    issuer: String,
    leeway_secs: i64,
}

/// A key ring holding the given verifying keys (marked as configured).
pub fn keyring_from_keys(verifying_keys: &[[u8; 32]]) -> Result<KeyRing, AuthError> {
    let ring = KeyRing::new();
    for bytes in verifying_keys {
        VerifyingKey::from_bytes(bytes)
            .map_err(|e| AuthError::Config(format!("invalid {FIELD_JWT_VERIFYING_KEYS}: {e}")))?;
        ring.merge(VerifyingKeyRecord {
            kid: key_id(bytes),
            public_key: *bytes,
            status: KeyStatus::Active,
            published_by: None,
            created_at: Utc::now(),
            revoked_at: None,
        });
    }
    Ok(ring)
}

/// The configured verifying keys, or the key derived from `signing_key`
/// when none are configured.
pub fn configured_verifying_keys(config: &JwtConfig) -> Vec<[u8; 32]> {
    if config.verifying_keys.is_empty() {
        config
            .signing_key
            .as_ref()
            .map(|seed| vec![SigningKey::from_bytes(seed).verifying_key().to_bytes()])
            .unwrap_or_default()
    } else {
        config.verifying_keys.clone()
    }
}

impl Ed25519Decoder {
    /// A decoder over a fixed set of keys.
    pub fn new(
        verifying_keys: &[[u8; 32]],
        issuer: impl Into<String>,
        leeway: std::time::Duration,
    ) -> Result<Self, AuthError> {
        if verifying_keys.is_empty() {
            return Err(AuthError::Config(format!(
                "missing {FIELD_JWT_VERIFYING_KEYS}"
            )));
        }
        Ok(Self::with_keyring(
            Arc::new(keyring_from_keys(verifying_keys)?),
            issuer,
            leeway,
        ))
    }

    /// A decoder reading keys from a shared, live [`KeyRing`].
    pub fn with_keyring(
        keys: Arc<KeyRing>,
        issuer: impl Into<String>,
        leeway: std::time::Duration,
    ) -> Self {
        Self {
            keys,
            issuer: issuer.into(),
            leeway_secs: i64::try_from(leeway.as_secs()).unwrap_or(i64::MAX),
        }
    }

    /// Build from `JwtConfig`: uses `verifying_keys`, or the key derived
    /// from `signing_key` when none are configured.
    pub fn from_config(config: &JwtConfig) -> Result<Self, AuthError> {
        Self::new(
            &configured_verifying_keys(config),
            config.issuer.clone(),
            config.leeway,
        )
    }
}

impl AccessTokenDecoder for Ed25519Decoder {
    fn decode(
        &self,
        token: &str,
        now: DateTime<Utc>,
        expiry: ExpiryCheck,
    ) -> Result<Claims, AuthError> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid("malformed token"));
        };

        // 1. Header: exactly EdDSA, known key.
        let header: Header = B64URL
            .decode(header_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| invalid("malformed header"))?;
        if header.alg != JWT_ALG {
            return Err(invalid("unsupported algorithm"));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| invalid("missing key id"))?;
        if self.keys.is_revoked(kid) {
            return Err(invalid("signing key revoked"));
        }
        let key = self
            .keys
            .active(kid)
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .ok_or_else(|| invalid("unknown key id"))?;

        // 2. Signature over `header.payload`.
        let sig_bytes: [u8; 64] = B64URL
            .decode(sig_b64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("malformed signature"))?;
        let signature = Signature::from_bytes(&sig_bytes);
        let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
        key.verify_strict(signing_input.as_bytes(), &signature)
            .map_err(|_| invalid("bad signature"))?;

        // 3. Claims.
        let payload: Payload = B64URL
            .decode(payload_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| invalid("malformed payload"))?;
        if payload.iss != self.issuer {
            return Err(invalid("wrong issuer"));
        }
        let now_secs = now.timestamp();
        if payload.iat > now_secs.saturating_add(self.leeway_secs) {
            return Err(invalid("issued in the future"));
        }
        if expiry == ExpiryCheck::Enforce && now_secs > payload.exp.saturating_add(self.leeway_secs)
        {
            return Err(invalid("expired"));
        }

        let uuid = |v: &str| Uuid::parse_str(v).map_err(|_| invalid("malformed claim"));
        Ok(Claims {
            sub: uuid(&payload.sub)?,
            sid: uuid(&payload.sid)?,
            jti: uuid(&payload.jti)?,
            generation: payload.generation,
            iss: payload.iss,
            iat: payload.iat,
            exp: payload.exp,
            authz: authz_from_wire(payload.rol, payload.prm, payload.pv),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SEED: [u8; 32] = [7u8; 32];
    const OTHER_SEED: [u8; 32] = [9u8; 32];
    const ISS: &str = "test-issuer";

    fn vk(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn claims(now: DateTime<Utc>) -> Claims {
        Claims {
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            generation: 3,
            iss: ISS.into(),
            iat: now.timestamp(),
            exp: now.timestamp() + 300,
            authz: None,
        }
    }

    #[test]
    fn authorization_claims_round_trip() {
        let seed = [9u8; 32];
        let issuer = Ed25519Issuer::new(&seed).unwrap();
        let now = Utc::now();
        let mut c = claims(now);
        c.authz = Some(AuthzClaims {
            roles: vec!["admin".into(), "user".into()],
            permissions: Some(EncodedPermissions {
                catalog_version: 7,
                bits: "Kw".into(),
                text: BTreeMap::from([(6, "250".into())]),
            }),
        });
        let token = issuer.mint(&c).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(token.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        assert_eq!(payload["rol"], serde_json::json!(["admin", "user"]));
        assert_eq!(
            payload["prm"],
            serde_json::json!({"b": "Kw", "t": {"6": "250"}})
        );
        assert_eq!(payload["pv"], 7);
        assert_eq!(
            decoder(&[vk(&seed)])
                .decode(&token, now, ExpiryCheck::Enforce)
                .unwrap(),
            c
        );

        // Permissions in use but nothing granted: only `pv` travels.
        c.authz = Some(AuthzClaims {
            roles: vec![],
            permissions: Some(EncodedPermissions {
                catalog_version: 7,
                ..Default::default()
            }),
        });
        let token = issuer.mint(&c).unwrap();
        assert_eq!(
            decoder(&[vk(&seed)])
                .decode(&token, now, ExpiryCheck::Enforce)
                .unwrap(),
            c
        );
        // No authorization data at all: none of the claims appear.
        c.authz = None;
        let token = issuer.mint(&c).unwrap();
        let payload =
            String::from_utf8(B64URL.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert!(!payload.contains("rol") && !payload.contains("prm") && !payload.contains("pv"));
    }

    fn decoder(keys: &[[u8; 32]]) -> Ed25519Decoder {
        Ed25519Decoder::new(keys, ISS, Duration::from_secs(30)).unwrap()
    }

    fn segments(token: &str) -> Vec<String> {
        token.split('.').map(String::from).collect()
    }

    #[test]
    fn round_trip_and_determinism() {
        let now = Utc::now();
        let c = claims(now);
        let issuer = Ed25519Issuer::new(&SEED).unwrap();
        let token = issuer.mint(&c).unwrap();
        assert_eq!(
            token,
            issuer.mint(&c).unwrap(),
            "minting must be deterministic"
        );
        let decoded = decoder(&[vk(&SEED)])
            .decode(&token, now, ExpiryCheck::Enforce)
            .unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let now = Utc::now();
        let token = Ed25519Issuer::new(&SEED)
            .unwrap()
            .mint(&claims(now))
            .unwrap();
        let mut s = segments(&token);
        let mut other = claims(now);
        other.sub = Uuid::new_v4();
        let forged = Ed25519Issuer::new(&SEED).unwrap().mint(&other).unwrap();
        s[1] = segments(&forged)[1].clone();
        let err = decoder(&[vk(&SEED)])
            .decode(&s.join("."), now, ExpiryCheck::Enforce)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(ref m) if m == "bad signature"));
    }

    #[test]
    fn foreign_algorithms_are_rejected() {
        let now = Utc::now();
        let token = Ed25519Issuer::new(&SEED)
            .unwrap()
            .mint(&claims(now))
            .unwrap();
        let kid = key_id(&vk(&SEED));
        for alg in ["none", "HS256", "RS256", "eddsa"] {
            let mut s = segments(&token);
            s[0] = B64URL.encode(format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"{kid}"}}"#));
            if alg == "none" {
                s[2] = String::new();
            }
            let err = decoder(&[vk(&SEED)])
                .decode(&s.join("."), now, ExpiryCheck::Enforce)
                .unwrap_err();
            assert!(
                matches!(err, AuthError::InvalidToken(ref m) if m == "unsupported algorithm"),
                "alg {alg}: {err:?}"
            );
        }
    }

    #[test]
    fn unknown_key_and_wrong_key_are_rejected() {
        let now = Utc::now();
        let token = Ed25519Issuer::new(&OTHER_SEED)
            .unwrap()
            .mint(&claims(now))
            .unwrap();
        let err = decoder(&[vk(&SEED)])
            .decode(&token, now, ExpiryCheck::Enforce)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(ref m) if m == "unknown key id"));

        // Rotation: both keys accepted.
        decoder(&[vk(&SEED), vk(&OTHER_SEED)])
            .decode(&token, now, ExpiryCheck::Enforce)
            .unwrap();
    }

    #[test]
    fn expiry_respects_leeway_and_ignore() {
        let issued = Utc::now() - chrono::Duration::seconds(400);
        let token = Ed25519Issuer::new(&SEED)
            .unwrap()
            .mint(&claims(issued))
            .unwrap();
        let d = decoder(&[vk(&SEED)]);
        let now = Utc::now();
        assert!(
            d.decode(&token, now, ExpiryCheck::Enforce).is_err(),
            "expired 100s ago"
        );
        assert!(d.decode(&token, now, ExpiryCheck::Ignore).is_ok());

        let within_leeway = issued + chrono::Duration::seconds(300 + 20);
        assert!(
            d.decode(&token, within_leeway, ExpiryCheck::Enforce)
                .is_ok()
        );
    }

    #[test]
    fn wrong_issuer_and_malformed_are_rejected() {
        let now = Utc::now();
        let mut c = claims(now);
        c.iss = "someone-else".into();
        let token = Ed25519Issuer::new(&SEED).unwrap().mint(&c).unwrap();
        let d = decoder(&[vk(&SEED)]);
        assert!(d.decode(&token, now, ExpiryCheck::Enforce).is_err());
        for bad in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(d.decode(bad, now, ExpiryCheck::Ignore).is_err(), "{bad:?}");
        }
    }
}
