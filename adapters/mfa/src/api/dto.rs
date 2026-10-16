//! Wire shapes of the second-factor endpoints.  Responses that carry a
//! secret (TOTP secret, otpauth URI, recovery codes) redact it in `Debug`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::model::{FactorView, MfaMethod};

/// Body of `POST /mfa/totp`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BeginTotpRequest {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TotpEnrollmentResponse {
    pub factor_id: Uuid,
    /// Base32, for manual entry.
    pub secret: String,
    /// Render as a QR code.
    pub otpauth_uri: String,
    pub expires_at: DateTime<Utc>,
}

/// Body of `POST /mfa/delivered`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeginDeliveredRequest {
    /// `email` or `sms`.
    pub method: MfaMethod,
    /// Email: defaults to the account's address.  SMS: an E.164 number.
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingDeliveryResponse {
    pub factor_id: Uuid,
    pub method: MfaMethod,
    pub destination_hint: String,
    pub code_expires_at: DateTime<Utc>,
}

/// Body of `POST /mfa/factors/{id}/confirm`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfirmEnrollmentRequest {
    pub code: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrollmentConfirmedResponse {
    pub factor: FactorView,
    /// Present when issued; show once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

/// A fresh code proving the user holds a factor.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StepUpRequest {
    /// `totp` | `email` | `sms` | `recovery_code`.
    pub method: String,
    pub code: String,
}

/// Body of `POST /mfa/step-up/code`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SendCodeRequest {
    /// `email` or `sms`; omit for the first enrolled one.
    #[serde(default)]
    pub method: Option<MfaMethod>,
}

/// Body of `POST /login/second-factor/code`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SendLoginCodeRequest {
    pub challenge_token: String,
    #[serde(default)]
    pub method: Option<MfaMethod>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeSentResponse {
    pub method: String,
    pub destination_hint: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryCodesResponse {
    /// Show once.
    pub recovery_codes: Vec<String>,
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for TotpEnrollmentResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrollmentResponse")
            .field("factor_id", &self.factor_id)
            .field("secret", &REDACTED)
            .field("otpauth_uri", &REDACTED)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for ConfirmEnrollmentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmEnrollmentRequest")
            .field("code", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for EnrollmentConfirmedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentConfirmedResponse")
            .field("factor", &self.factor)
            .field(
                "recovery_codes",
                &self
                    .recovery_codes
                    .as_ref()
                    .map(|c| format!("<{} redacted>", c.len())),
            )
            .finish()
    }
}

impl std::fmt::Debug for StepUpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpRequest")
            .field("method", &self.method)
            .field("code", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for SendLoginCodeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendLoginCodeRequest")
            .field("challenge_token", &REDACTED)
            .field("method", &self.method)
            .finish()
    }
}

impl std::fmt::Debug for RecoveryCodesResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecoveryCodesResponse(<{} redacted>)",
            self.recovery_codes.len()
        )
    }
}
