//! [`MfaService`] — what a user (or an administrator) does with second
//! factors: enroll, confirm, list, remove, reset; plus sending the email /
//! SMS code of a pending login.
//!
//! Every `user_id` comes from a token the host verified.  Enrollment
//! accepts password-only sessions (so required-but-unenrolled users can
//! enroll); weakening the protection — removing a factor, new recovery
//! codes — needs a fresh code ([`StepUpProof`]).

use async_trait::async_trait;
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::security::authentication::ChallengeDelivery;

use crate::model::{
    EnrollmentConfirmed, FactorView, MfaMethod, MfaStatus, PendingDelivery, StepUpProof,
    TotpEnrollment,
};

#[async_trait]
pub trait MfaService: Send + Sync {
    /// The user's active factors, whether policy requires one, and the
    /// recovery codes left.
    async fn status(&self, user_id: Uuid) -> Result<MfaStatus, AuthError>;

    /// The user's active factors.
    async fn factors(&self, user_id: Uuid) -> Result<Vec<FactorView>, AuthError>;

    /// Start a TOTP enrollment: a new secret to show as a QR code.  Replaces
    /// an unconfirmed one.
    async fn begin_totp_enrollment(
        &self,
        user_id: Uuid,
        label: Option<String>,
    ) -> Result<TotpEnrollment, AuthError>;

    /// Start an email / SMS enrollment and send its first code.  Email
    /// defaults to the account's address; SMS needs an E.164 number.
    async fn begin_delivered_enrollment(
        &self,
        user_id: Uuid,
        method: MfaMethod,
        destination: Option<String>,
        label: Option<String>,
    ) -> Result<PendingDelivery, AuthError>;

    /// Send a new code for a pending email / SMS enrollment.
    async fn resend_enrollment_code(
        &self,
        user_id: Uuid,
        factor_id: Uuid,
    ) -> Result<PendingDelivery, AuthError>;

    /// Confirm a pending factor with its first code.  With the user's first
    /// factor, recovery codes are issued too.
    async fn confirm_enrollment(
        &self,
        user_id: Uuid,
        factor_id: Uuid,
        code: &str,
    ) -> Result<EnrollmentConfirmed, AuthError>;

    /// Send a code for a [`StepUpProof`] through an email / SMS factor
    /// (`None`: the first one in `AUTH_MFA_METHODS` order).
    async fn send_step_up_code(
        &self,
        user_id: Uuid,
        method: Option<MfaMethod>,
    ) -> Result<ChallengeDelivery, AuthError>;

    /// Replace the user's recovery codes.  Show the result once.
    async fn regenerate_recovery_codes(
        &self,
        user_id: Uuid,
        proof: StepUpProof,
    ) -> Result<Vec<String>, AuthError>;

    /// Remove one of the user's factors (with the last one, the recovery
    /// codes go too).  Ends the user's sessions when
    /// `AUTH_MFA_END_SESSIONS_ON_REMOVAL` is on.
    async fn remove_factor(
        &self,
        user_id: Uuid,
        factor_id: Uuid,
        proof: StepUpProof,
    ) -> Result<(), AuthError>;

    /// Administrative: delete every factor and recovery code of a user
    /// (e.g. a lost phone, after identity checks).  Returns the factors
    /// deleted.  No proof required — guard the caller.
    async fn reset(&self, user_id: Uuid) -> Result<u64, AuthError>;

    /// Send (or re-send) the email / SMS code of a pending login.  `None`
    /// picks the first enrolled delivered method in `AUTH_MFA_METHODS`
    /// order.
    async fn send_login_code(
        &self,
        challenge_token: &str,
        method: Option<MfaMethod>,
    ) -> Result<ChallengeDelivery, AuthError>;
}
