//! Base32 encodings: RFC 4648 (TOTP secrets, as authenticator apps expect)
//! and Crockford's alphabet (recovery codes — no I, L, O or U).

/// RFC 4648 alphabet.
const RFC4648: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Crockford's alphabet.
pub(crate) const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// RFC 4648 base32 without padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(RFC4648[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(RFC4648[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decode RFC 4648 base32, ignoring padding, spaces and case.  `None` on
/// any other character.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let v = RFC4648.iter().position(|&a| a == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// The canonical Crockford form of user input: uppercase, separators and
/// spaces dropped, and the look-alikes O → 0, I / L → 1.  `None` if any
/// other character is outside the alphabet.
pub fn crockford_normalize(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10, without padding.
    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(decode("mzxw6ytboi======").unwrap(), b"foobar");
        assert!(decode("MZXW1").is_none(), "1 is not in the alphabet");
    }

    #[test]
    fn crockford_input_is_forgiving() {
        assert_eq!(crockford_normalize("abcde-fghjk").unwrap(), "ABCDEFGHJK");
        assert_eq!(crockford_normalize(" o0 il ").unwrap(), "0011");
        assert!(crockford_normalize("ABCDU").is_none(), "U is excluded");
        assert!(crockford_normalize("ABC!").is_none());
    }
}
