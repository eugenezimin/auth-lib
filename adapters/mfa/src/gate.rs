//! The login side of z-auth-mfa: [`MfaServiceImpl`] as z-auth's
//! [`SecondFactorGate`].
//!
//! Once the password matched, [`on_password_verified`] applies the
//! enforcement policy and, for users with a factor, stores a challenge and
//! returns its token (sending an email / SMS code right away when the user
//! has no authenticator app).  [`verify`] then checks the second step:
//!
//! 1. the token's secret against the stored hash (constant time), that the
//!    challenge is unconsumed and unexpired, and — when configured — that
//!    the same client is answering;
//! 2. that the user is not locked out;
//! 3. one attempt is counted **before** the code is checked, so parallel
//!    guesses cannot exceed `AUTH_MFA_CHALLENGE_MAX_ATTEMPTS`;
//! 4. the code: TOTP (each step accepted once), the email / SMS code sent
//!    for this challenge, or a recovery code (consumed);
//! 5. a failure counts toward the user's lockout; a success consumes the
//!    challenge and clears the failures.
//!
//! [`on_password_verified`]: SecondFactorGate::on_password_verified
//! [`verify`]: SecondFactorGate::verify

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::identity::user::model::UserWithRoles;
use z_auth::security::authentication::{
    ClientContext, LoginChallenge, SecondFactorDecision, SecondFactorGate, SecondFactorProof,
    VerifiedSecondFactor,
};
use z_auth::security::session::model::RequestTraits;

use crate::config::{Enforcement, Unenrolled};
use crate::constants::METHOD_RECOVERY_CODE;
use crate::crypto::codes::{self, CodeKind, normalize_numeric, normalize_recovery};
use crate::model::{Challenge, Factor, MfaMethod, NewChallenge, ProofMethod};
use crate::service_impl::MfaServiceImpl;
use z_auth::conf::constants::AMR_OTP;

impl MfaServiceImpl {
    /// The challenge a token names, if it is genuine and still open.
    pub(crate) async fn open_challenge(
        &self,
        token: &str,
    ) -> Result<(Challenge, DateTime<Utc>), AuthError> {
        let (id, secret) =
            codes::parse_challenge_token(token).ok_or(AuthError::ChallengeExpired)?;
        let (challenge, now) = self
            .repo
            .find_challenge(id)
            .await?
            .ok_or(AuthError::ChallengeExpired)?;
        let genuine = self.hasher.matches(
            CodeKind::ChallengeSecret,
            id,
            &secret,
            &challenge.secret_hash,
        );
        if !genuine || challenge.consumed_at.is_some() || challenge.expires_at <= now {
            return Err(AuthError::ChallengeExpired);
        }
        Ok((challenge, now))
    }

    /// Methods a challenge accepts, preferred first.
    async fn challenge_methods(
        &self,
        user_id: Uuid,
        factors: &[Factor],
    ) -> Result<Vec<String>, AuthError> {
        let mut methods: Vec<String> = factors.iter().map(|f| f.method.to_string()).collect();
        if self.recovery_enabled() && self.repo.count_recovery_codes(user_id).await? > 0 {
            methods.push(METHOD_RECOVERY_CODE.into());
        }
        Ok(methods)
    }

    /// The `amr` value `code` proves for `challenge`, or `None`.
    async fn prove(
        &self,
        challenge: &Challenge,
        now: DateTime<Utc>,
        method: Option<ProofMethod>,
        code: &str,
    ) -> Result<Option<&'static str>, AuthError> {
        let user_id = challenge.user_id;
        let factors = self.active_factors(user_id).await?;
        let totp_factor = factors.iter().find(|f| f.method == MfaMethod::Totp);
        // The factor the challenge's code was sent through.
        let sent_through = challenge
            .code
            .as_ref()
            .and_then(|c| factors.iter().find(|f| f.id == c.factor_id));

        let try_totp = async |code: &str| -> Result<Option<&'static str>, AuthError> {
            match totp_factor {
                Some(f) => Ok(self
                    .check_totp(f, code)
                    .await?
                    .then_some(MfaMethod::Totp.amr())),
                None => Ok(None),
            }
        };
        let try_delivered = async |code: &str| -> Result<Option<&'static str>, AuthError> {
            let Some(f) = sent_through else {
                return Ok(None);
            };
            let pending = challenge.code.as_ref().map(|c| &c.code);
            if !self.delivered_code_matches(pending, challenge.id, code, now) {
                return Ok(None);
            }
            self.repo.mark_factor_used(f.id).await?;
            Ok(Some(f.method.amr()))
        };
        let try_recovery = async |code: &str| -> Result<Option<&'static str>, AuthError> {
            Ok(self.check_recovery(user_id, code).await?.then_some(AMR_OTP))
        };

        match method {
            Some(ProofMethod::Factor(MfaMethod::Totp)) => try_totp(code).await,
            Some(ProofMethod::Factor(m)) => {
                if sent_through.is_some_and(|f| f.method == m) {
                    try_delivered(code).await
                } else {
                    Ok(None)
                }
            }
            Some(ProofMethod::RecoveryCode) => try_recovery(code).await,
            // No method given: whatever the code can be, cheapest first.
            None => {
                let totp_digits = totp_factor.and_then(|f| f.totp).map(|p| p.digits);
                if let Some(digits) = totp_digits
                    && normalize_numeric(code, digits).is_some()
                    && let Some(amr) = try_totp(code).await?
                {
                    return Ok(Some(amr));
                }
                if sent_through.is_some()
                    && normalize_numeric(code, self.settings.codes.digits).is_some()
                    && let Some(amr) = try_delivered(code).await?
                {
                    return Ok(Some(amr));
                }
                if normalize_recovery(code, self.settings.recovery.length).is_some() {
                    return try_recovery(code).await;
                }
                Ok(None)
            }
        }
    }
}

#[async_trait]
impl SecondFactorGate for MfaServiceImpl {
    async fn on_password_verified(
        &self,
        account: &UserWithRoles,
        ctx: &ClientContext,
    ) -> Result<SecondFactorDecision, AuthError> {
        if self.settings.enforcement == Enforcement::Off {
            return Ok(SecondFactorDecision::Proceed);
        }
        let user_id = account.user.id;
        let factors = self.active_factors(user_id).await?;
        if factors.is_empty() {
            if self.required_for(account) && self.settings.unenrolled == Unenrolled::Deny {
                return Err(AuthError::SecondFactorNotEnrolled);
            }
            return Ok(SecondFactorDecision::Proceed);
        }
        self.ensure_unlocked(user_id).await?;

        let id = Uuid::new_v4();
        let (token, secret) = codes::challenge_token(id)?;
        let issued = ctx.issue_context(None);
        let challenge = self
            .repo
            .create_challenge(
                NewChallenge {
                    id,
                    user_id,
                    secret_hash: self.hasher.hash(CodeKind::ChallengeSecret, id, &secret),
                    created_ip: issued.ip,
                    user_agent: issued.user_agent,
                    fingerprint_hash: issued.fingerprint_hash,
                },
                self.settings.challenge.ttl,
            )
            .await?;

        let has_totp = factors.iter().any(|f| f.method == MfaMethod::Totp);
        let delivery = match factors.iter().find(|f| f.method.is_delivered()) {
            Some(f) if self.settings.codes.auto_send && !has_totp => {
                Some(self.send_challenge_code(&challenge, f).await?)
            }
            _ => None,
        };
        Ok(SecondFactorDecision::Challenge(LoginChallenge {
            challenge_token: token,
            expires_at: challenge.expires_at,
            methods: self.challenge_methods(user_id, &factors).await?,
            delivery,
        }))
    }

    async fn verify(
        &self,
        proof: &SecondFactorProof,
        ctx: &ClientContext,
    ) -> Result<VerifiedSecondFactor, AuthError> {
        let (challenge, now) = self.open_challenge(&proof.challenge_token).await?;
        if let Some(rule) = &self.settings.challenge.client_match {
            let first = RequestTraits {
                ip: challenge.created_ip,
                user_agent: challenge.user_agent.as_deref(),
                fingerprint_hash: challenge.fingerprint_hash.as_ref(),
            };
            let issued = ctx.issue_context(None);
            if !first.same_client(&issued.traits(), rule) {
                return Err(AuthError::ChallengeExpired);
            }
        }
        let user_id = challenge.user_id;
        self.ensure_unlocked(user_id).await?;
        let method = proof
            .method
            .as_deref()
            .map(|m| {
                m.parse::<ProofMethod>()
                    .map_err(|_| AuthError::UnsupportedSecondFactor(m.to_string()))
            })
            .transpose()?;
        if self
            .repo
            .record_challenge_attempt(challenge.id, self.settings.challenge.max_attempts)
            .await?
            .is_none()
        {
            return Err(AuthError::ChallengeExpired);
        }

        let Some(amr) = self.prove(&challenge, now, method, &proof.code).await? else {
            return Err(self.failed(user_id).await);
        };
        if !self.repo.consume_challenge(challenge.id).await? {
            return Err(AuthError::ChallengeExpired);
        }
        self.repo.clear_failures(user_id).await?;
        Ok(VerifiedSecondFactor {
            user_id,
            amr: vec![amr.to_string()],
        })
    }
}
