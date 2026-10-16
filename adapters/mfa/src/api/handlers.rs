//! Framework-agnostic second-factor endpoints, in the style of z-auth's own
//! `controller::api::handlers`.  The host routes them, verifies the bearer
//! token and passes its `sub` as `user_id`:
//!
//! ```rust,ignore
//! // axum example (host application code)
//! async fn begin_totp(
//!     State(app): State<App>,
//!     Bearer(claims): Bearer,            // verified with auth.verifier()
//!     Json(req): Json<BeginTotpRequest>,
//! ) -> Result<Json<TotpEnrollmentResponse>, MyError> {
//!     Ok(Json(handlers::begin_totp(app.mfa.as_ref(), claims.sub, req).await?))
//! }
//! ```
//!
//! The second login step itself is z-auth's
//! `controller::api::handlers::complete_login` (`POST /login/second-factor`).

use uuid::Uuid;
use z_auth::controller::api::ApiError;

use crate::api::dto::{
    BeginDeliveredRequest, BeginTotpRequest, CodeSentResponse, ConfirmEnrollmentRequest,
    EnrollmentConfirmedResponse, PendingDeliveryResponse, RecoveryCodesResponse, SendCodeRequest,
    SendLoginCodeRequest, StepUpRequest, TotpEnrollmentResponse,
};
use crate::model::{FactorView, MfaStatus};
use crate::service::MfaService;

/// `GET /mfa`
pub async fn status(mfa: &dyn MfaService, user_id: Uuid) -> Result<MfaStatus, ApiError> {
    Ok(mfa.status(user_id).await?)
}

/// `GET /mfa/factors`
pub async fn factors(mfa: &dyn MfaService, user_id: Uuid) -> Result<Vec<FactorView>, ApiError> {
    Ok(mfa.factors(user_id).await?)
}

/// `POST /mfa/totp` — start a TOTP enrollment.
pub async fn begin_totp(
    mfa: &dyn MfaService,
    user_id: Uuid,
    req: BeginTotpRequest,
) -> Result<TotpEnrollmentResponse, ApiError> {
    Ok(mfa.begin_totp_enrollment(user_id, req.label).await?.into())
}

/// `POST /mfa/delivered` — start an email / SMS enrollment (sends a code).
pub async fn begin_delivered(
    mfa: &dyn MfaService,
    user_id: Uuid,
    req: BeginDeliveredRequest,
) -> Result<PendingDeliveryResponse, ApiError> {
    Ok(mfa
        .begin_delivered_enrollment(user_id, req.method, req.destination, req.label)
        .await?
        .into())
}

/// `POST /mfa/factors/{id}/code` — re-send a pending enrollment's code.
pub async fn resend_enrollment_code(
    mfa: &dyn MfaService,
    user_id: Uuid,
    factor_id: Uuid,
) -> Result<PendingDeliveryResponse, ApiError> {
    Ok(mfa.resend_enrollment_code(user_id, factor_id).await?.into())
}

/// `POST /mfa/factors/{id}/confirm` — activate a pending factor.
pub async fn confirm_enrollment(
    mfa: &dyn MfaService,
    user_id: Uuid,
    factor_id: Uuid,
    req: ConfirmEnrollmentRequest,
) -> Result<EnrollmentConfirmedResponse, ApiError> {
    Ok(mfa
        .confirm_enrollment(user_id, factor_id, &req.code)
        .await?
        .into())
}

/// `POST /mfa/step-up/code` — send a code for a step-up proof.
pub async fn send_step_up_code(
    mfa: &dyn MfaService,
    user_id: Uuid,
    req: SendCodeRequest,
) -> Result<CodeSentResponse, ApiError> {
    Ok(mfa.send_step_up_code(user_id, req.method).await?.into())
}

/// `POST /mfa/recovery-codes` — replace the recovery codes.
pub async fn regenerate_recovery_codes(
    mfa: &dyn MfaService,
    user_id: Uuid,
    proof: StepUpRequest,
) -> Result<RecoveryCodesResponse, ApiError> {
    let recovery_codes = mfa
        .regenerate_recovery_codes(user_id, proof.try_into()?)
        .await?;
    Ok(RecoveryCodesResponse { recovery_codes })
}

/// `DELETE /mfa/factors/{id}` — remove a factor (with a step-up proof).
pub async fn remove_factor(
    mfa: &dyn MfaService,
    user_id: Uuid,
    factor_id: Uuid,
    proof: StepUpRequest,
) -> Result<(), ApiError> {
    Ok(mfa
        .remove_factor(user_id, factor_id, proof.try_into()?)
        .await?)
}

/// `POST /login/second-factor/code` — send (or re-send) the email / SMS
/// code of a pending login.  Unauthenticated: the challenge token is the
/// credential.
pub async fn send_login_code(
    mfa: &dyn MfaService,
    req: SendLoginCodeRequest,
) -> Result<CodeSentResponse, ApiError> {
    Ok(mfa
        .send_login_code(&req.challenge_token, req.method)
        .await?
        .into())
}
