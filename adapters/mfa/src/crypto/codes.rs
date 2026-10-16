//! One-time codes and challenge tokens: generation, keyed hashing, parsing,
//! and masking of delivery destinations.
//!
//! Nothing secret is stored in clear: recovery codes, email / SMS codes and
//! the secret part of challenge tokens are kept as HMAC-SHA256 under the
//! configured hash key, each with its own domain label and owner id, so a
//! leaked table can neither be replayed nor brute-forced offline.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use z_auth::AuthError;

use crate::constants::{CHALLENGE_SECRET_LEN, CHALLENGE_TOKEN_VERSION};
use crate::crypto::base32::{CROCKFORD, crockford_normalize};

type HmacSha256 = Hmac<Sha256>;

/// `len` bytes from the operating system's CSPRNG.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, AuthError> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|e| AuthError::Internal(format!("OS RNG failure: {e}")))?;
    Ok(buf)
}

/// What a keyed hash is of; keeps the hashes of different kinds apart.
#[derive(Debug, Clone, Copy)]
pub enum CodeKind {
    Recovery,
    /// An email / SMS code.
    Delivered,
    ChallengeSecret,
}

impl CodeKind {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Recovery => b"z-auth-mfa/recovery",
            Self::Delivered => b"z-auth-mfa/code",
            Self::ChallengeSecret => b"z-auth-mfa/challenge",
        }
    }
}

/// Keyed hashing of codes under the configured hash key.
#[derive(Clone)]
pub struct CodeHasher {
    key: Vec<u8>,
}

impl CodeHasher {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// HMAC(key, label ‖ 0 ‖ owner ‖ value).  `owner` is the user,
    /// factor or challenge the value belongs to.
    pub fn hash(&self, kind: CodeKind, owner: Uuid, value: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(kind.label());
        mac.update(&[0]);
        mac.update(owner.as_bytes());
        mac.update(value);
        mac.finalize().into_bytes().into()
    }

    /// Whether `value` hashes to `expected`, in constant time.
    pub fn matches(&self, kind: CodeKind, owner: Uuid, value: &[u8], expected: &[u8; 32]) -> bool {
        self.hash(kind, owner, value).ct_eq(expected).into()
    }
}

impl std::fmt::Debug for CodeHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodeHasher(<redacted>)")
    }
}

/// A uniformly random numeric code of `digits` digits.
pub fn numeric_code(digits: u32) -> Result<String, AuthError> {
    let mut out = String::with_capacity(digits as usize);
    while out.len() < digits as usize {
        for b in random_bytes(16)? {
            // Rejection sampling: 250 = 25 × 10 keeps the digits uniform.
            if b < 250 && out.len() < digits as usize {
                out.push(char::from(b'0' + b % 10));
            }
        }
    }
    Ok(out)
}

/// Normalise a numeric code as typed: surrounding and inner spaces or
/// dashes dropped.  `None` unless exactly `digits` digits remain.
pub fn normalize_numeric(code: &str, digits: u32) -> Option<String> {
    let cleaned: String = code
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '\t'))
        .collect();
    (cleaned.len() == digits as usize && cleaned.bytes().all(|b| b.is_ascii_digit()))
        .then_some(cleaned)
}

/// A random recovery code of `length` Crockford characters, grouped by
/// five with dashes for display (`7KQ2M-X9D4R`).
pub fn recovery_code(length: usize) -> Result<String, AuthError> {
    let mut raw = String::with_capacity(length);
    while raw.len() < length {
        for b in random_bytes(32)? {
            // 32 divides 256: masking keeps the characters uniform.
            if raw.len() < length {
                raw.push(char::from(CROCKFORD[(b & 0x1f) as usize]));
            }
        }
    }
    Ok(raw
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).expect("ASCII"))
        .collect::<Vec<_>>()
        .join("-"))
}

/// The canonical form of a recovery code as typed, if it can be one.
pub fn normalize_recovery(code: &str, length: usize) -> Option<String> {
    crockford_normalize(code).filter(|c| c.len() == length)
}

/// A new challenge token `mfa1.<id>.<secret>` and its secret.
pub fn challenge_token(id: Uuid) -> Result<(String, Vec<u8>), AuthError> {
    let secret = random_bytes(CHALLENGE_SECRET_LEN)?;
    let token = format!(
        "{CHALLENGE_TOKEN_VERSION}.{}.{}",
        id.simple(),
        B64URL.encode(&secret)
    );
    Ok((token, secret))
}

/// The id and secret of a challenge token; `None` if malformed.
pub fn parse_challenge_token(token: &str) -> Option<(Uuid, Vec<u8>)> {
    let mut parts = token.trim().split('.');
    let (Some(version), Some(id), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if version != CHALLENGE_TOKEN_VERSION {
        return None;
    }
    let id = Uuid::try_parse(id).ok()?;
    let secret = B64URL.decode(secret).ok()?;
    (secret.len() == CHALLENGE_SECRET_LEN).then_some((id, secret))
}

/// `jane.doe@example.com` → `j*******@example.com`.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            let stars = local.chars().count().saturating_sub(1).clamp(3, 8);
            format!("{first}{}@{domain}", "*".repeat(stars))
        }
        None => "***".into(),
    }
}

/// `+15551234567` → `*******4567`.
pub fn mask_phone(phone: &str) -> String {
    let digits: Vec<char> = phone.chars().filter(char::is_ascii_digit).collect();
    let keep = digits.len().min(4);
    let tail: String = digits[digits.len() - keep..].iter().collect();
    format!("{}{tail}", "*".repeat(digits.len() - keep))
}

/// `+` and 8–15 digits (E.164), spaces, dots, dashes and parentheses
/// dropped.  `None` if it is not a phone number.
pub fn normalize_phone(phone: &str) -> Option<String> {
    let trimmed = phone.trim();
    let rest = trimmed.strip_prefix('+')?;
    let digits: String = rest
        .chars()
        .filter(|c| !matches!(c, ' ' | '.' | '-' | '(' | ')'))
        .collect();
    (digits.len() >= 8 && digits.len() <= 15 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("+{digits}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_keyed_typed_and_bound_to_their_owner() {
        let h = CodeHasher::new(vec![7; 32]);
        let owner = Uuid::from_u128(1);
        let hash = h.hash(CodeKind::Recovery, owner, b"ABC");
        assert!(h.matches(CodeKind::Recovery, owner, b"ABC", &hash));
        assert!(!h.matches(CodeKind::Recovery, owner, b"ABD", &hash));
        assert!(!h.matches(CodeKind::Delivered, owner, b"ABC", &hash));
        assert!(!h.matches(CodeKind::Recovery, Uuid::from_u128(2), b"ABC", &hash));
        assert!(!CodeHasher::new(vec![8; 32]).matches(CodeKind::Recovery, owner, b"ABC", &hash));
    }

    #[test]
    fn numeric_codes_have_the_requested_digits() {
        for digits in [6, 8, 10] {
            let code = numeric_code(digits).unwrap();
            assert_eq!(code.len(), digits as usize);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
        assert_eq!(normalize_numeric(" 123-456 ", 6).as_deref(), Some("123456"));
        assert_eq!(normalize_numeric("12345", 6), None);
        assert_eq!(normalize_numeric("12345a", 6), None);
    }

    #[test]
    fn recovery_codes_round_trip_through_normalisation() {
        let code = recovery_code(10).unwrap();
        assert_eq!(code.len(), 11, "two groups of five");
        assert_eq!(&code[5..6], "-");
        let typed = code.to_lowercase().replace('-', " ");
        assert_eq!(
            normalize_recovery(&typed, 10).unwrap(),
            code.replace('-', "")
        );
        assert_eq!(normalize_recovery("ABCDE", 10), None);
    }

    #[test]
    fn challenge_tokens_parse_back() {
        let id = Uuid::new_v4();
        let (token, secret) = challenge_token(id).unwrap();
        assert!(token.starts_with("mfa1."));
        assert_eq!(parse_challenge_token(&token), Some((id, secret)));
        assert_eq!(parse_challenge_token("mfa2.x.y"), None);
        assert_eq!(parse_challenge_token(&format!("{token}.extra")), None);
        assert_eq!(parse_challenge_token("garbage"), None);
    }

    #[test]
    fn destinations_are_masked_and_phones_normalised() {
        assert_eq!(mask_email("jane.doe@example.com"), "j*******@example.com");
        assert_eq!(mask_email("a@b.io"), "a***@b.io");
        assert_eq!(mask_phone("+15551234567"), "*******4567");
        assert_eq!(
            normalize_phone("+1 (555) 123-4567").as_deref(),
            Some("+15551234567")
        );
        assert_eq!(normalize_phone("5551234567"), None, "needs a country code");
        assert_eq!(normalize_phone("+12"), None);
    }
}
