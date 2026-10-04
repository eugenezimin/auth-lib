//! User input validation.

use crate::error::AuthError;

/// Canonical form of an email address: trimmed and lowercased.
///
/// Applied before every write and lookup so that `Alice@X.com` and
/// `alice@x.com` are the same account.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Basic email format validation.
pub fn validate_email(email: &str) -> Result<(), AuthError> {
    let valid = match email.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    };

    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidEmail(format!(
            "'{email}' is not a valid email address"
        )))
    }
}
