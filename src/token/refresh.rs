//! HMAC-SHA256 refresh tokens — feature `crypto`.
//!
//! Format: `v1.<session_id>.<generation>.<base64url(mac)>` where
//! `mac = HMAC-SHA256(refresh_secret, domain ‖ session_id ‖ generation ‖ session_secret)`.
//!
//! Nothing token-shaped is stored: the server re-derives a generation's
//! token from the session row, which requires both the DB row (session
//! secret) and the server-wide `refresh_secret`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::config::SessionConfig;
use crate::constants::{FIELD_REFRESH_SECRET, REFRESH_TOKEN_VERSION};
use crate::error::AuthError;
use crate::token::codec::RefreshTokenCodec;
use crate::token::model::RefreshToken;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation prefix for the MAC input.
const MAC_DOMAIN: &[u8] = b"auth-lib/refresh/v1";

/// Built-in [`RefreshTokenCodec`].
pub struct HmacRefreshCodec {
    key: Vec<u8>,
}

impl HmacRefreshCodec {
    pub fn new(refresh_secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key: refresh_secret.into(),
        }
    }

    /// Build from `SessionConfig::refresh_secret`.
    pub fn from_config(config: &SessionConfig) -> Result<Self, AuthError> {
        config
            .refresh_secret
            .clone()
            .map(Self::new)
            .ok_or_else(|| AuthError::Config(format!("missing {FIELD_REFRESH_SECRET}")))
    }

    fn mac(&self, session_id: Uuid, generation: u32, session_secret: &[u8]) -> HmacSha256 {
        // Keys of any length are accepted by HMAC; `new_from_slice` cannot fail.
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(MAC_DOMAIN);
        mac.update(session_id.as_bytes());
        mac.update(&generation.to_be_bytes());
        mac.update(session_secret);
        mac
    }
}

impl RefreshTokenCodec for HmacRefreshCodec {
    fn issue(
        &self,
        session_id: Uuid,
        generation: u32,
        session_secret: &[u8],
    ) -> Result<String, AuthError> {
        let tag = self
            .mac(session_id, generation, session_secret)
            .finalize()
            .into_bytes();
        Ok(format!(
            "{REFRESH_TOKEN_VERSION}.{}.{generation}.{}",
            session_id.simple(),
            B64URL.encode(tag)
        ))
    }

    fn parse(&self, token: &str) -> Result<RefreshToken, AuthError> {
        let malformed = || AuthError::InvalidToken("malformed refresh token".into());
        let mut parts = token.split('.');
        let (Some(version), Some(sid), Some(generation), Some(mac), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(malformed());
        };
        if version != REFRESH_TOKEN_VERSION {
            return Err(malformed());
        }
        Ok(RefreshToken {
            session_id: Uuid::parse_str(sid).map_err(|_| malformed())?,
            generation: generation.parse().map_err(|_| malformed())?,
            mac: B64URL.decode(mac).map_err(|_| malformed())?,
        })
    }

    fn verify(&self, token: &RefreshToken, session_secret: &[u8]) -> bool {
        self.mac(token.session_id, token.generation, session_secret)
            .verify_slice(&token.mac)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"session-secret";

    fn codec() -> HmacRefreshCodec {
        HmacRefreshCodec::new(vec![1u8; 32])
    }

    #[test]
    fn issue_parse_verify_round_trip() {
        let sid = Uuid::new_v4();
        let token = codec().issue(sid, 4, SECRET).unwrap();
        assert_eq!(
            token,
            codec().issue(sid, 4, SECRET).unwrap(),
            "deterministic"
        );
        let parsed = codec().parse(&token).unwrap();
        assert_eq!(parsed.session_id, sid);
        assert_eq!(parsed.generation, 4);
        assert!(codec().verify(&parsed, SECRET));
    }

    #[test]
    fn tampering_and_wrong_secrets_fail() {
        let sid = Uuid::new_v4();
        let mut parsed = codec()
            .parse(&codec().issue(sid, 4, SECRET).unwrap())
            .unwrap();
        assert!(!codec().verify(&parsed, b"other-session-secret"));
        assert!(!HmacRefreshCodec::new(vec![2u8; 32]).verify(&parsed, SECRET));

        parsed.generation = 5;
        assert!(
            !codec().verify(&parsed, SECRET),
            "generation is bound by the MAC"
        );
    }

    #[test]
    fn malformed_tokens_fail_to_parse() {
        let sid = Uuid::new_v4().simple();
        for bad in [
            "",
            "v1",
            &format!("v2.{sid}.1.AAAA"),
            "v1.not-a-uuid.1.AAAA",
            &format!("v1.{sid}.-1.AAAA"),
            &format!("v1.{sid}.1.!!!"),
            &format!("v1.{sid}.1.AAAA.extra"),
        ] {
            assert!(codec().parse(bad).is_err(), "{bad:?}");
        }
    }
}
