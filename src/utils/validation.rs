//! Validation of the codes shared by roles and permissions.

use crate::conf::constants::MAX_CODE_LEN;
use crate::utils::error::AuthError;

/// Role, permission and option codes: `^[a-z][a-z0-9_.:-]*$`, at most
/// [`MAX_CODE_LEN`] characters.  Codes are immutable identifiers that end
/// up in tokens and application code.
pub fn validate_code(code: &str) -> Result<(), AuthError> {
    let mut chars = code.chars();
    let valid_start = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let valid_rest = chars.all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-')
    });
    if valid_start && valid_rest && code.len() <= MAX_CODE_LEN {
        Ok(())
    } else {
        Err(AuthError::InvalidCode(format!(
            "'{code}' must match ^[a-z][a-z0-9_.:-]*$ and be at most {MAX_CODE_LEN} characters"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        for ok in ["admin", "reports.export", "a1_b-c:d"] {
            assert!(validate_code(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Admin",
            "1abc",
            "has space",
            "ünï",
            &"a".repeat(MAX_CODE_LEN + 1),
        ] {
            assert!(validate_code(bad).is_err(), "{bad}");
        }
    }
}
