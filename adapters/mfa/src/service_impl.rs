//! [`MfaServiceImpl`] — the default [`MfaService`], which is also the
//! [`SecondFactorGate`](z_auth::security::authentication::SecondFactorGate)
//! z-auth consults at login (see [`crate::gate`]).
//!
//! Stored rows carry the store's timestamps, and expiry is judged against
//! the store's clock (returned with each read).  TOTP steps come from the
//! local clock, like z-auth's stateless token checks.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::identity::user::model::UserWithRoles;
use z_auth::identity::user::repository::UserRepository;
use z_auth::identity::user::validation::{normalize_email, validate_email};
use z_auth::security::authentication::ChallengeDelivery;
use z_auth::security::session::RevocationReason;
use z_auth::security::token::TokenRevocationService;
use z_auth::utils::clock::Clock;

use crate::config::{Enforcement, MfaSettings};
use crate::constants::MAX_FACTOR_LABEL_LEN;
use crate::crypto::base32;
use crate::crypto::codes::{
    self, CodeHasher, CodeKind, mask_email, mask_phone, normalize_numeric, normalize_phone,
    normalize_recovery,
};
use crate::crypto::sealer::SecretSealer;
use crate::crypto::totp;
use crate::model::{
    Challenge, EnrollmentConfirmed, Factor, FactorStatus, FactorView, MfaMethod, MfaStatus,
    NewCode, NewFactor, PendingCode, PendingDelivery, ProofMethod, SendOutcome, StepUpProof,
    TotpEnrollment, TotpParams,
};
use crate::repository::{CodeLimits, MfaRepository};
use crate::sender::{CodeDelivery, CodePurpose, CodeSender};
use crate::service::MfaService;

/// Default implementation of [`MfaService`].
pub struct MfaServiceImpl {
    pub(crate) settings: MfaSettings,
    pub(crate) repo: Arc<dyn MfaRepository>,
    users: Arc<dyn UserRepository>,
    revocation: Arc<dyn TokenRevocationService>,
    sender: Option<Arc<dyn CodeSender>>,
    sealer: Arc<dyn SecretSealer>,
    pub(crate) hasher: CodeHasher,
    pub(crate) clock: Arc<dyn Clock>,
    /// Shown in authenticator apps.
    issuer: String,
}

impl MfaServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings: MfaSettings,
        repo: Arc<dyn MfaRepository>,
        users: Arc<dyn UserRepository>,
        revocation: Arc<dyn TokenRevocationService>,
        sender: Option<Arc<dyn CodeSender>>,
        sealer: Arc<dyn SecretSealer>,
        clock: Arc<dyn Clock>,
        default_issuer: &str,
    ) -> Self {
        let issuer = settings
            .totp
            .issuer
            .clone()
            .unwrap_or_else(|| default_issuer.to_string());
        Self {
            hasher: CodeHasher::new(settings.keys.hash_key.clone()),
            settings,
            repo,
            users,
            revocation,
            sender,
            sealer,
            clock,
            issuer,
        }
    }

    // ── Policy ───────────────────────────────────────────────────────────────

    pub(crate) fn enabled(&self, method: MfaMethod) -> bool {
        self.settings.methods.contains(&method)
    }

    fn ensure_enabled(&self, method: MfaMethod) -> Result<(), AuthError> {
        if self.enabled(method) {
            Ok(())
        } else {
            Err(AuthError::UnsupportedSecondFactor(method.to_string()))
        }
    }

    pub(crate) fn recovery_enabled(&self) -> bool {
        self.settings.recovery.count > 0
    }

    /// Whether the enforcement policy requires a second factor of `account`.
    pub(crate) fn required_for(&self, account: &UserWithRoles) -> bool {
        match &self.settings.enforcement {
            Enforcement::Off | Enforcement::Optional => false,
            Enforcement::Required => true,
            Enforcement::Roles(codes) => account.roles.iter().any(|r| codes.contains(&r.code)),
        }
    }

    pub(crate) fn code_limits(&self) -> CodeLimits {
        CodeLimits {
            ttl: self.settings.codes.ttl,
            resend_after: self.settings.codes.resend_after,
            max_sends: self.settings.codes.max_sends,
        }
    }

    // ── Factors ──────────────────────────────────────────────────────────────

    /// Active factors of enabled methods, in `AUTH_MFA_METHODS` order.
    pub(crate) async fn active_factors(&self, user_id: Uuid) -> Result<Vec<Factor>, AuthError> {
        let mut factors: Vec<Factor> = self
            .repo
            .list_factors(user_id)
            .await?
            .into_iter()
            .filter(|f| f.status == FactorStatus::Active && self.enabled(f.method))
            .collect();
        factors.sort_by_key(|f| self.settings.methods.iter().position(|m| *m == f.method));
        Ok(factors)
    }

    /// The first active factor of `method`, or of any delivered method when
    /// `method` is `None`.
    pub(crate) fn delivered_factor(
        &self,
        factors: &[Factor],
        method: Option<MfaMethod>,
    ) -> Result<Factor, AuthError> {
        if let Some(m) = method {
            if !m.is_delivered() {
                return Err(AuthError::UnsupportedSecondFactor(m.to_string()));
            }
            self.ensure_enabled(m)?;
        }
        factors
            .iter()
            .find(|f| f.method.is_delivered() && method.is_none_or(|m| f.method == m))
            .cloned()
            .ok_or(AuthError::SecondFactorNotEnrolled)
    }

    fn view(f: &Factor) -> FactorView {
        FactorView {
            id: f.id,
            method: f.method,
            label: f.label.clone(),
            destination_hint: f.destination_hint.clone(),
            created_at: f.created_at,
            confirmed_at: f.confirmed_at,
            last_used_at: f.last_used_at,
        }
    }

    /// Associated data binding a sealed value to its factor row.
    fn aad(user_id: Uuid, factor_id: Uuid, what: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + what.len());
        aad.extend_from_slice(user_id.as_bytes());
        aad.extend_from_slice(factor_id.as_bytes());
        aad.extend_from_slice(what.as_bytes());
        aad
    }

    fn totp_secret(&self, f: &Factor) -> Result<Vec<u8>, AuthError> {
        let sealed = f
            .secret_sealed
            .as_deref()
            .ok_or_else(|| AuthError::Internal("TOTP factor without a secret".into()))?;
        self.sealer
            .open(sealed, &Self::aad(f.user_id, f.id, "totp-secret"))
    }

    fn destination(&self, f: &Factor) -> Result<String, AuthError> {
        let sealed = f
            .destination_sealed
            .as_deref()
            .ok_or_else(|| AuthError::Internal("delivered factor without a destination".into()))?;
        let bytes = self
            .sealer
            .open(sealed, &Self::aad(f.user_id, f.id, "destination"))?;
        String::from_utf8(bytes).map_err(|_| AuthError::Internal("destination is not UTF-8".into()))
    }

    fn label(label: Option<String>) -> Option<String> {
        label
            .map(|l| {
                l.trim()
                    .chars()
                    .take(MAX_FACTOR_LABEL_LEN)
                    .collect::<String>()
            })
            .filter(|l| !l.is_empty())
    }

    async fn ensure_not_enrolled(&self, user_id: Uuid, method: MfaMethod) -> Result<(), AuthError> {
        let enrolled = self
            .repo
            .list_factors(user_id)
            .await?
            .iter()
            .any(|f| f.method == method && f.status == FactorStatus::Active);
        if enrolled {
            return Err(AuthError::SecondFactorAlreadyEnrolled);
        }
        Ok(())
    }

    // ── Codes ────────────────────────────────────────────────────────────────

    fn sender(&self) -> Result<&Arc<dyn CodeSender>, AuthError> {
        self.sender
            .as_ref()
            .ok_or_else(|| AuthError::Config("z-auth-mfa: no CodeSender configured".into()))
    }

    async fn deliver(
        &self,
        f: &Factor,
        code: String,
        purpose: CodePurpose,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let destination = self.destination(f)?;
        self.sender()?
            .send(CodeDelivery {
                user_id: f.user_id,
                method: f.method,
                destination,
                code,
                purpose,
                expires_at,
            })
            .await
    }

    fn sent(outcome: SendOutcome) -> Result<DateTime<Utc>, AuthError> {
        match outcome {
            SendOutcome::Stored { expires_at } => Ok(expires_at),
            SendOutcome::TooSoon | SendOutcome::LimitReached => Err(AuthError::CodeResendTooSoon),
            SendOutcome::NotFound => Err(AuthError::ChallengeExpired),
        }
    }

    /// Store a new code on a factor and send it.
    async fn send_factor_code(
        &self,
        f: &Factor,
        purpose: CodePurpose,
    ) -> Result<DateTime<Utc>, AuthError> {
        let code = codes::numeric_code(self.settings.codes.digits)?;
        let hash = self.hasher.hash(CodeKind::Delivered, f.id, code.as_bytes());
        let expires_at = Self::sent(
            self.repo
                .set_factor_code(f.id, hash, self.code_limits())
                .await?,
        )?;
        self.deliver(f, code, purpose, expires_at).await?;
        Ok(expires_at)
    }

    /// Store a new code on a login challenge and send it through `f`.
    pub(crate) async fn send_challenge_code(
        &self,
        challenge: &Challenge,
        f: &Factor,
    ) -> Result<ChallengeDelivery, AuthError> {
        let code = codes::numeric_code(self.settings.codes.digits)?;
        let hash = self
            .hasher
            .hash(CodeKind::Delivered, challenge.id, code.as_bytes());
        let expires_at = Self::sent(
            self.repo
                .set_challenge_code(
                    challenge.id,
                    NewCode {
                        code_hash: hash,
                        factor_id: f.id,
                    },
                    self.code_limits(),
                )
                .await?,
        )?;
        self.deliver(f, code, CodePurpose::Login, expires_at)
            .await?;
        Ok(ChallengeDelivery {
            method: f.method.to_string(),
            destination_hint: f.destination_hint.clone().unwrap_or_default(),
            expires_at,
        })
    }

    /// Whether `code` is the unexpired delivered code `pending` (kept for
    /// `owner`).
    pub(crate) fn delivered_code_matches(
        &self,
        pending: Option<&PendingCode>,
        owner: Uuid,
        code: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(pending) = pending else {
            return false;
        };
        let Some(code) = normalize_numeric(code, self.settings.codes.digits) else {
            return false;
        };
        let matches = self.hasher.matches(
            CodeKind::Delivered,
            owner,
            code.as_bytes(),
            &pending.code_hash,
        );
        matches && pending.expires_at > now
    }

    /// The TOTP step `code` is valid for under `f`, if any (no replay check).
    fn totp_step(&self, f: &Factor, code: &str) -> Result<Option<u64>, AuthError> {
        let params = f
            .totp
            .ok_or_else(|| AuthError::Internal("TOTP factor without parameters".into()))?;
        let secret = self.totp_secret(f)?;
        Ok(totp::verify(
            &secret,
            code,
            self.clock.now().timestamp(),
            &params,
            self.settings.totp.skew_steps,
        ))
    }

    /// A TOTP code from an active factor, accepted once.
    pub(crate) async fn check_totp(&self, f: &Factor, code: &str) -> Result<bool, AuthError> {
        match self.totp_step(f, code)? {
            Some(step) => self.repo.advance_totp_step(f.id, step).await,
            None => Ok(false),
        }
    }

    /// A recovery code of `user_id`, consumed if it matches.
    pub(crate) async fn check_recovery(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, AuthError> {
        if !self.recovery_enabled() {
            return Ok(false);
        }
        let Some(code) = normalize_recovery(code, self.settings.recovery.length) else {
            return Ok(false);
        };
        let hash = self
            .hasher
            .hash(CodeKind::Recovery, user_id, code.as_bytes());
        self.repo.consume_recovery_code(user_id, &hash).await
    }

    /// Issue a fresh set of recovery codes (replacing any).
    async fn issue_recovery_codes(&self, user_id: Uuid) -> Result<Vec<String>, AuthError> {
        let count = self.settings.recovery.count as usize;
        let length = self.settings.recovery.length;
        let mut shown = Vec::with_capacity(count);
        let mut hashes = Vec::with_capacity(count);
        while shown.len() < count {
            let code = codes::recovery_code(length)?;
            let canonical = code.replace('-', "");
            let hash = self
                .hasher
                .hash(CodeKind::Recovery, user_id, canonical.as_bytes());
            if !hashes.contains(&hash) {
                hashes.push(hash);
                shown.push(code);
            }
        }
        self.repo.replace_recovery_codes(user_id, &hashes).await?;
        Ok(shown)
    }

    // ── Failures ─────────────────────────────────────────────────────────────

    pub(crate) async fn ensure_unlocked(&self, user_id: Uuid) -> Result<(), AuthError> {
        if self.settings.lockout.threshold > 0 && self.repo.lock_state(user_id).await?.is_locked() {
            return Err(AuthError::SecondFactorLocked);
        }
        Ok(())
    }

    /// Count a wrong proof; the error to return.
    pub(crate) async fn failed(&self, user_id: Uuid) -> AuthError {
        let lockout = self.settings.lockout;
        if lockout.threshold == 0 {
            return AuthError::InvalidSecondFactor;
        }
        match self
            .repo
            .record_failure(user_id, lockout.window, lockout.threshold, lockout.duration)
            .await
        {
            Ok(state) if state.is_locked() => AuthError::SecondFactorLocked,
            Ok(_) => AuthError::InvalidSecondFactor,
            Err(e) => e,
        }
    }

    /// Check a step-up proof against the user's active factors.
    async fn verify_step_up(&self, user_id: Uuid, proof: &StepUpProof) -> Result<(), AuthError> {
        self.ensure_unlocked(user_id).await?;
        let factors = self.active_factors(user_id).await?;
        if factors.is_empty() {
            return Err(AuthError::SecondFactorNotEnrolled);
        }
        let factor_of = |m: MfaMethod| factors.iter().find(|f| f.method == m);
        let ok = match proof.method {
            ProofMethod::Factor(MfaMethod::Totp) => match factor_of(MfaMethod::Totp) {
                Some(f) => self.check_totp(f, &proof.code).await?,
                None => false,
            },
            ProofMethod::Factor(m) => match factor_of(m) {
                Some(f) => {
                    let max = self.settings.challenge.max_attempts;
                    match self.repo.record_factor_attempt(f.id, max).await? {
                        None => false,
                        Some(_) => {
                            // Re-read for the code just counted and the
                            // store's clock.
                            let (f, now) = self
                                .repo
                                .find_factor(f.id)
                                .await?
                                .ok_or(AuthError::SecondFactorNotFound)?;
                            let ok = self.delivered_code_matches(
                                f.code.as_ref(),
                                f.id,
                                &proof.code,
                                now,
                            );
                            if ok {
                                self.repo.mark_factor_used(f.id).await?;
                            }
                            ok
                        }
                    }
                }
                None => false,
            },
            ProofMethod::RecoveryCode => self.check_recovery(user_id, &proof.code).await?,
        };
        if !ok {
            return Err(self.failed(user_id).await);
        }
        self.repo.clear_failures(user_id).await
    }

    async fn end_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        if self.settings.end_sessions_on_removal {
            self.revocation
                .end_all_for_user(user_id, RevocationReason::SecondFactorChanged)
                .await?;
        }
        Ok(())
    }

    fn otpauth_uri(&self, account: &str, secret: &str, params: &TotpParams) -> String {
        let issuer = percent_encode(&self.issuer);
        format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}\
             &algorithm={}&digits={}&period={}",
            params.algorithm.as_str(),
            params.digits,
            params.period_secs,
            account = percent_encode(account),
        )
    }
}

/// RFC 3986 percent-encoding of everything but unreserved characters.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[async_trait]
impl MfaService for MfaServiceImpl {
    async fn status(&self, user_id: Uuid) -> Result<MfaStatus, AuthError> {
        let account = self
            .users
            .find_with_roles_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let factors = self.active_factors(user_id).await?;
        Ok(MfaStatus {
            factors: factors.iter().map(Self::view).collect(),
            required: self.required_for(&account),
            recovery_codes_left: self.repo.count_recovery_codes(user_id).await?,
            available_methods: self.settings.methods.clone(),
        })
    }

    async fn factors(&self, user_id: Uuid) -> Result<Vec<FactorView>, AuthError> {
        Ok(self
            .active_factors(user_id)
            .await?
            .iter()
            .map(Self::view)
            .collect())
    }

    async fn begin_totp_enrollment(
        &self,
        user_id: Uuid,
        label: Option<String>,
    ) -> Result<TotpEnrollment, AuthError> {
        self.ensure_enabled(MfaMethod::Totp)?;
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        self.ensure_not_enrolled(user_id, MfaMethod::Totp).await?;

        let id = Uuid::new_v4();
        let secret = codes::random_bytes(self.settings.totp.secret_bytes)?;
        let params = TotpParams {
            algorithm: self.settings.totp.algorithm,
            digits: self.settings.totp.digits,
            period_secs: self.settings.totp.period.as_secs(),
        };
        let factor = self
            .repo
            .insert_pending_factor(
                NewFactor {
                    id,
                    user_id,
                    method: MfaMethod::Totp,
                    label: Self::label(label),
                    secret_sealed: Some(
                        self.sealer
                            .seal(&secret, &Self::aad(user_id, id, "totp-secret"))?,
                    ),
                    totp: Some(params),
                    destination_sealed: None,
                    destination_hint: None,
                },
                self.settings.enrollment_ttl,
            )
            .await?;
        let encoded = base32::encode(&secret);
        Ok(TotpEnrollment {
            factor_id: factor.id,
            otpauth_uri: self.otpauth_uri(&user.email, &encoded, &params),
            secret: encoded,
            expires_at: factor
                .expires_at
                .ok_or_else(|| AuthError::Internal("pending factor without expiry".into()))?,
        })
    }

    async fn begin_delivered_enrollment(
        &self,
        user_id: Uuid,
        method: MfaMethod,
        destination: Option<String>,
        label: Option<String>,
    ) -> Result<PendingDelivery, AuthError> {
        if !method.is_delivered() {
            return Err(AuthError::UnsupportedSecondFactor(method.to_string()));
        }
        self.ensure_enabled(method)?;
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let (destination, hint) = match method {
            MfaMethod::Email => {
                let email = normalize_email(&destination.unwrap_or(user.email));
                validate_email(&email)?;
                let hint = mask_email(&email);
                (email, hint)
            }
            _ => {
                let raw = destination.ok_or_else(|| {
                    AuthError::InvalidDestination("a phone number is required".into())
                })?;
                let phone = normalize_phone(&raw).ok_or_else(|| {
                    AuthError::InvalidDestination(
                        "expected an international number such as +15551234567".into(),
                    )
                })?;
                let hint = mask_phone(&phone);
                (phone, hint)
            }
        };
        self.ensure_not_enrolled(user_id, method).await?;

        let id = Uuid::new_v4();
        let factor = self
            .repo
            .insert_pending_factor(
                NewFactor {
                    id,
                    user_id,
                    method,
                    label: Self::label(label),
                    secret_sealed: None,
                    totp: None,
                    destination_sealed: Some(self.sealer.seal(
                        destination.as_bytes(),
                        &Self::aad(user_id, id, "destination"),
                    )?),
                    destination_hint: Some(hint.clone()),
                },
                self.settings.enrollment_ttl,
            )
            .await?;
        let code_expires_at = self
            .send_factor_code(&factor, CodePurpose::Enrollment)
            .await?;
        Ok(PendingDelivery {
            factor_id: factor.id,
            method,
            destination_hint: hint,
            code_expires_at,
        })
    }

    async fn resend_enrollment_code(
        &self,
        user_id: Uuid,
        factor_id: Uuid,
    ) -> Result<PendingDelivery, AuthError> {
        let (factor, now) = self
            .repo
            .find_factor(factor_id)
            .await?
            .filter(|(f, _)| f.user_id == user_id)
            .ok_or(AuthError::SecondFactorNotFound)?;
        if factor.status != FactorStatus::Pending || !factor.method.is_delivered() {
            return Err(AuthError::SecondFactorNotFound);
        }
        if factor.expires_at.is_none_or(|t| t <= now) {
            return Err(AuthError::ChallengeExpired);
        }
        let code_expires_at = self
            .send_factor_code(&factor, CodePurpose::Enrollment)
            .await?;
        Ok(PendingDelivery {
            factor_id,
            method: factor.method,
            destination_hint: factor.destination_hint.unwrap_or_default(),
            code_expires_at,
        })
    }

    async fn confirm_enrollment(
        &self,
        user_id: Uuid,
        factor_id: Uuid,
        code: &str,
    ) -> Result<EnrollmentConfirmed, AuthError> {
        let (factor, now) = self
            .repo
            .find_factor(factor_id)
            .await?
            .filter(|(f, _)| f.user_id == user_id)
            .ok_or(AuthError::SecondFactorNotFound)?;
        self.ensure_enabled(factor.method)?;
        if factor.status == FactorStatus::Active {
            return Err(AuthError::SecondFactorAlreadyEnrolled);
        }
        if factor.expires_at.is_none_or(|t| t <= now) {
            return Err(AuthError::ChallengeExpired);
        }
        self.ensure_unlocked(user_id).await?;

        let (ok, used_step) = if factor.method == MfaMethod::Totp {
            let step = self.totp_step(&factor, code)?;
            (step.is_some(), step)
        } else {
            let max = self.settings.challenge.max_attempts;
            if self
                .repo
                .record_factor_attempt(factor.id, max)
                .await?
                .is_none()
            {
                return Err(AuthError::ChallengeExpired);
            }
            let ok = self.delivered_code_matches(factor.code.as_ref(), factor.id, code, now);
            (ok, None)
        };
        if !ok {
            return Err(self.failed(user_id).await);
        }
        if !self
            .repo
            .activate_factor(factor.id, user_id, used_step)
            .await?
        {
            return Err(AuthError::ChallengeExpired);
        }
        self.repo.clear_failures(user_id).await?;

        let recovery_codes =
            if self.recovery_enabled() && self.repo.count_recovery_codes(user_id).await? == 0 {
                Some(self.issue_recovery_codes(user_id).await?)
            } else {
                None
            };
        let (factor, _) = self
            .repo
            .find_factor(factor.id)
            .await?
            .ok_or(AuthError::SecondFactorNotFound)?;
        Ok(EnrollmentConfirmed {
            factor: Self::view(&factor),
            recovery_codes,
        })
    }

    async fn send_step_up_code(
        &self,
        user_id: Uuid,
        method: Option<MfaMethod>,
    ) -> Result<ChallengeDelivery, AuthError> {
        let factors = self.active_factors(user_id).await?;
        let factor = self.delivered_factor(&factors, method)?;
        let expires_at = self.send_factor_code(&factor, CodePurpose::StepUp).await?;
        Ok(ChallengeDelivery {
            method: factor.method.to_string(),
            destination_hint: factor.destination_hint.unwrap_or_default(),
            expires_at,
        })
    }

    async fn regenerate_recovery_codes(
        &self,
        user_id: Uuid,
        proof: StepUpProof,
    ) -> Result<Vec<String>, AuthError> {
        if !self.recovery_enabled() {
            return Err(AuthError::UnsupportedSecondFactor(
                crate::constants::METHOD_RECOVERY_CODE.into(),
            ));
        }
        self.verify_step_up(user_id, &proof).await?;
        self.issue_recovery_codes(user_id).await
    }

    async fn remove_factor(
        &self,
        user_id: Uuid,
        factor_id: Uuid,
        proof: StepUpProof,
    ) -> Result<(), AuthError> {
        let owned = self
            .repo
            .list_factors(user_id)
            .await?
            .iter()
            .any(|f| f.id == factor_id && f.status == FactorStatus::Active);
        if !owned {
            return Err(AuthError::SecondFactorNotFound);
        }
        self.verify_step_up(user_id, &proof).await?;
        if !self.repo.delete_factor(factor_id, user_id).await? {
            return Err(AuthError::SecondFactorNotFound);
        }
        let left = self
            .repo
            .list_factors(user_id)
            .await?
            .iter()
            .any(|f| f.status == FactorStatus::Active);
        if !left {
            // Recovery codes stand in for a factor; with none left they
            // would only be a way around enrolling again.
            self.repo.replace_recovery_codes(user_id, &[]).await?;
        }
        self.end_sessions(user_id).await
    }

    async fn reset(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let deleted = self.repo.delete_all(user_id).await?;
        if deleted > 0 {
            self.end_sessions(user_id).await?;
        }
        Ok(deleted)
    }

    async fn send_login_code(
        &self,
        challenge_token: &str,
        method: Option<MfaMethod>,
    ) -> Result<ChallengeDelivery, AuthError> {
        let (challenge, _) = self.open_challenge(challenge_token).await?;
        let factors = self.active_factors(challenge.user_id).await?;
        let factor = self.delivered_factor(&factors, method)?;
        self.send_challenge_code(&challenge, &factor).await
    }
}

#[cfg(test)]
mod tests {
    use super::percent_encode;

    #[test]
    fn otpauth_labels_are_percent_encoded() {
        assert_eq!(percent_encode("Acme Inc."), "Acme%20Inc.");
        assert_eq!(percent_encode("a+b@x.io"), "a%2Bb%40x.io");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }
}
