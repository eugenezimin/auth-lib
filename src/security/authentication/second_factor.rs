//! Hook a login consults once the password matched, installed by an
//! extension (e.g. z-auth-mfa): it may ask for a second factor before any
//! session exists, and later verifies the proof that completes the login.

use async_trait::async_trait;
use uuid::Uuid;

use crate::identity::user::model::UserWithRoles;
use crate::security::authentication::model::{ClientContext, LoginChallenge, SecondFactorProof};
use crate::utils::error::AuthError;

/// What [`SecondFactorGate::on_password_verified`] decided.
#[derive(Debug, Clone)]
pub enum SecondFactorDecision {
    /// Open the session now (no second factor needed).
    Proceed,
    /// Ask the client for a second factor; no session is opened yet.
    Challenge(LoginChallenge),
}

/// A proof the gate accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSecondFactor {
    /// The user the challenge was issued to.
    pub user_id: Uuid,
    /// RFC 8176 methods the proof adds to the session's `amr` (e.g.
    /// `["otp"]`).  z-auth adds `pwd` and `mfa`.
    pub amr: Vec<String>,
}

#[async_trait]
pub trait SecondFactorGate: Send + Sync {
    /// After the password matched and the account is active, before any
    /// session exists.  May also refuse the login (e.g.
    /// [`AuthError::SecondFactorLocked`]).
    async fn on_password_verified(
        &self,
        account: &UserWithRoles,
        ctx: &ClientContext,
    ) -> Result<SecondFactorDecision, AuthError>;

    /// Check a proof against its challenge, consuming the challenge on
    /// success.
    async fn verify(
        &self,
        proof: &SecondFactorProof,
        ctx: &ClientContext,
    ) -> Result<VerifiedSecondFactor, AuthError>;
}
