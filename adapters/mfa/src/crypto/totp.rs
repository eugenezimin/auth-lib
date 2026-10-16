//! HOTP (RFC 4226) and TOTP (RFC 6238) with SHA-1, SHA-256 or SHA-512.
//!
//! Verification computes every candidate in the skew window and compares
//! them all in constant time, so timing reveals neither the code nor which
//! step matched.  Replay protection (a step is accepted once) is the
//! caller's: see `MfaRepository::advance_totp_step`.

use hmac::{Hmac, KeyInit, Mac};
use subtle::ConstantTimeEq;

use crate::model::{TotpAlgorithm, TotpParams};

fn mac(algorithm: TotpAlgorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    fn run<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(message);
        m.finalize().into_bytes().to_vec()
    }
    match algorithm {
        TotpAlgorithm::Sha1 => run::<Hmac<sha1::Sha1>>(key, message),
        TotpAlgorithm::Sha256 => run::<Hmac<sha2::Sha256>>(key, message),
        TotpAlgorithm::Sha512 => run::<Hmac<sha2::Sha512>>(key, message),
    }
}

/// The HOTP value of `counter`, zero-padded to `digits`.
pub fn hotp(key: &[u8], counter: u64, algorithm: TotpAlgorithm, digits: u32) -> String {
    let hash = mac(algorithm, key, &counter.to_be_bytes());
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let value = u64::from(binary) % 10u64.pow(digits);
    format!("{value:0width$}", width = digits as usize)
}

/// The time step of `unix_secs`.
pub fn step_at(unix_secs: i64, period_secs: u64) -> u64 {
    u64::try_from(unix_secs).unwrap_or(0) / period_secs.max(1)
}

/// The TOTP code at `unix_secs`.
pub fn totp(key: &[u8], unix_secs: i64, params: &TotpParams) -> String {
    hotp(
        key,
        step_at(unix_secs, params.period_secs),
        params.algorithm,
        params.digits,
    )
}

/// The latest step within `skew` steps of `unix_secs` whose code equals
/// `code`, or `None`.
pub fn verify(
    key: &[u8],
    code: &str,
    unix_secs: i64,
    params: &TotpParams,
    skew: u32,
) -> Option<u64> {
    let code = code.trim();
    let well_formed =
        code.len() == params.digits as usize && code.bytes().all(|b| b.is_ascii_digit());
    let current = step_at(unix_secs, params.period_secs);
    let mut matched: Option<u64> = None;
    for step in current.saturating_sub(u64::from(skew))..=current.saturating_add(u64::from(skew)) {
        let candidate = hotp(key, step, params.algorithm, params.digits);
        // Every candidate is computed and compared, whatever the input.
        let equal: bool = candidate.as_bytes().ct_eq(code.as_bytes()).into();
        if equal && well_formed {
            matched = Some(step);
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED20: &[u8] = b"12345678901234567890";
    const SEED32: &[u8] = b"12345678901234567890123456789012";
    const SEED64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    /// RFC 4226 Appendix D.
    #[test]
    fn hotp_rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(SEED20, counter as u64, TotpAlgorithm::Sha1, 6), *code);
        }
    }

    /// RFC 6238 Appendix B (8 digits, 30 s).
    #[test]
    fn totp_rfc6238_vectors() {
        let cases: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in cases {
            for (alg, seed, code) in [
                (TotpAlgorithm::Sha1, SEED20, sha1),
                (TotpAlgorithm::Sha256, SEED32, sha256),
                (TotpAlgorithm::Sha512, SEED64, sha512),
            ] {
                let params = TotpParams {
                    algorithm: alg,
                    digits: 8,
                    period_secs: 30,
                };
                assert_eq!(totp(seed, t, &params), code, "{alg:?} at {t}");
                assert_eq!(verify(seed, code, t, &params, 0), Some(step_at(t, 30)));
            }
        }
    }

    #[test]
    fn the_skew_window_bounds_accepted_steps() {
        let params = TotpParams {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_secs: 30,
        };
        let now = 1_700_000_000;
        let previous = totp(SEED20, now - 30, &params);
        let two_back = totp(SEED20, now - 60, &params);
        let next = totp(SEED20, now + 30, &params);
        assert_eq!(
            verify(SEED20, &previous, now, &params, 1),
            Some(step_at(now - 30, 30))
        );
        assert_eq!(
            verify(SEED20, &next, now, &params, 1),
            Some(step_at(now + 30, 30))
        );
        assert_eq!(verify(SEED20, &two_back, now, &params, 1), None);
        assert_eq!(verify(SEED20, &previous, now, &params, 0), None);
    }

    #[test]
    fn malformed_codes_never_match() {
        let params = TotpParams {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_secs: 30,
        };
        let code = totp(SEED20, 59, &params);
        assert_eq!(
            verify(SEED20, &format!(" {code} "), 59, &params, 0),
            Some(1)
        );
        assert_eq!(verify(SEED20, &code[..5], 59, &params, 0), None);
        assert_eq!(verify(SEED20, "", 59, &params, 0), None);
        assert_eq!(verify(SEED20, "abcdef", 59, &params, 0), None);
    }
}
