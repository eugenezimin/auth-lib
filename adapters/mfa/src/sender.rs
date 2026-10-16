//! [`CodeSender`] — how email and SMS codes leave the service.  The host
//! implements it with its mail / SMS provider; z-auth-mfa only generates,
//! hashes and checks the codes.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;

use crate::model::MfaMethod;

/// Why a code is sent (pick a message template from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePurpose {
    /// The second step of a login.
    Login,
    /// Confirming a new email / SMS factor.
    Enrollment,
    /// Confirming a sensitive change (removing a factor, new recovery
    /// codes).
    StepUp,
}

/// One code to deliver.
#[derive(Clone)]
pub struct CodeDelivery {
    pub user_id: Uuid,
    /// `Email` or `Sms`.
    pub method: MfaMethod,
    /// Email address or E.164 phone number.
    pub destination: String,
    pub code: String,
    pub purpose: CodePurpose,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait CodeSender: Send + Sync {
    /// Deliver `delivery.code` to `delivery.destination`.  Report failures
    /// as [`AuthError::CodeDeliveryFailed`].
    async fn send(&self, delivery: CodeDelivery) -> Result<(), AuthError>;
}

impl std::fmt::Debug for CodeDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeDelivery")
            .field("user_id", &self.user_id)
            .field("method", &self.method)
            .field("destination", &"<redacted>")
            .field("code", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
