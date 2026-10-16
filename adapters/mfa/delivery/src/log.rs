//! The development sender: codes go to the log, nowhere else.

use async_trait::async_trait;
use z_auth::AuthError;
use z_auth_mfa::{CodeDelivery, CodeSender};

/// Logs email / SMS codes (at `WARN`, through `tracing`) instead of
/// delivering them — provider `log`.  Development only: anyone who can read
/// the logs can sign in as the user.
pub struct LogCodeSender;

#[async_trait]
impl CodeSender for LogCodeSender {
    async fn send(&self, d: CodeDelivery) -> Result<(), AuthError> {
        tracing::warn!(
            user_id = %d.user_id,
            method = %d.method,
            destination = %d.destination,
            code = %d.code,
            purpose = ?d.purpose,
            expires_at = %d.expires_at,
            "DEV ONLY: second-factor code not delivered"
        );
        Ok(())
    }
}
