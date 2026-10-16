//! Conversions between the second-factor DTOs and domain models.

use z_auth::AuthError;
use z_auth::security::authentication::ChallengeDelivery;

use crate::api::dto::{
    CodeSentResponse, EnrollmentConfirmedResponse, PendingDeliveryResponse, StepUpRequest,
    TotpEnrollmentResponse,
};
use crate::model::{EnrollmentConfirmed, PendingDelivery, StepUpProof, TotpEnrollment};

impl From<TotpEnrollment> for TotpEnrollmentResponse {
    fn from(e: TotpEnrollment) -> Self {
        Self {
            factor_id: e.factor_id,
            secret: e.secret,
            otpauth_uri: e.otpauth_uri,
            expires_at: e.expires_at,
        }
    }
}

impl From<PendingDelivery> for PendingDeliveryResponse {
    fn from(p: PendingDelivery) -> Self {
        Self {
            factor_id: p.factor_id,
            method: p.method,
            destination_hint: p.destination_hint,
            code_expires_at: p.code_expires_at,
        }
    }
}

impl From<EnrollmentConfirmed> for EnrollmentConfirmedResponse {
    fn from(c: EnrollmentConfirmed) -> Self {
        Self {
            factor: c.factor,
            recovery_codes: c.recovery_codes,
        }
    }
}

impl From<ChallengeDelivery> for CodeSentResponse {
    fn from(d: ChallengeDelivery) -> Self {
        Self {
            method: d.method,
            destination_hint: d.destination_hint,
            expires_at: d.expires_at,
        }
    }
}

impl TryFrom<StepUpRequest> for StepUpProof {
    type Error = AuthError;

    fn try_from(r: StepUpRequest) -> Result<Self, AuthError> {
        Ok(Self {
            method: r
                .method
                .parse()
                .map_err(|_| AuthError::UnsupportedSecondFactor(r.method.clone()))?,
            code: r.code,
        })
    }
}
