//! Password policy enforcement.

use crate::config::PasswordPolicy;
use crate::error::AuthError;

/// Check `password` against the configured [`PasswordPolicy`].
pub fn validate_password(password: &str, policy: &PasswordPolicy) -> Result<(), AuthError> {
    if password.chars().count() < policy.min_length {
        return Err(AuthError::WeakPassword(format!(
            "must be at least {} characters",
            policy.min_length
        )));
    }
    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthError::WeakPassword(
            "must contain at least one uppercase letter".into(),
        ));
    }
    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::WeakPassword(
            "must contain at least one digit".into(),
        ));
    }
    Ok(())
}
