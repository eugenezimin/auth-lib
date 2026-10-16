//! Second-factor domain models — factors, recovery codes, login challenges
//! and lockout state, plus what the service hands back to the host.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::repository`]
//! - Service contract     → [`crate::service`]
//!
//! Every timestamp in a stored record is assigned by the store.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::constants::METHOD_RECOVERY_CODE;
use z_auth::conf::constants::{AMR_OTP, AMR_SMS};

/// A kind of second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaMethod {
    /// Time-based one-time passwords from an authenticator app (RFC 6238).
    Totp,
    /// A code sent by email through the host's [`CodeSender`](crate::CodeSender).
    Email,
    /// A code sent by SMS through the host's [`CodeSender`](crate::CodeSender).
    Sms,
}

impl MfaMethod {
    pub const ALL: [MfaMethod; 3] = [Self::Totp, Self::Email, Self::Sms];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }

    /// Whether codes are delivered (email, SMS) rather than generated.
    pub fn is_delivered(self) -> bool {
        matches!(self, Self::Email | Self::Sms)
    }

    /// The RFC 8176 `amr` value a successful proof adds.
    pub fn amr(self) -> &'static str {
        match self {
            Self::Totp | Self::Email => AMR_OTP,
            Self::Sms => AMR_SMS,
        }
    }
}

impl std::fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for MfaMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "totp" => Ok(Self::Totp),
            "email" => Ok(Self::Email),
            "sms" => Ok(Self::Sms),
            other => Err(format!("unknown method '{other}' (totp | email | sms)")),
        }
    }
}

/// What a second-step proof claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofMethod {
    Factor(MfaMethod),
    RecoveryCode,
}

impl ProofMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Factor(m) => m.as_str(),
            Self::RecoveryCode => METHOD_RECOVERY_CODE,
        }
    }
}

impl std::str::FromStr for ProofMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if s.trim() == METHOD_RECOVERY_CODE {
            Ok(Self::RecoveryCode)
        } else {
            s.parse().map(Self::Factor)
        }
    }
}

/// HMAC hash of TOTP codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    /// Name in `otpauth://` URIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl std::str::FromStr for TotpAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            other => Err(format!(
                "unknown algorithm '{other}' (sha1 | sha256 | sha512)"
            )),
        }
    }
}

/// The parameters a TOTP factor was enrolled with (kept per factor, so a
/// configuration change does not break existing authenticators).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period_secs: u64,
}

/// Lifecycle state of a factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorStatus {
    /// Enrolled but not confirmed with a first code yet; expires.
    Pending,
    Active,
}

/// A one-time code waiting to be entered: its keyed hash and send history.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingCode {
    pub code_hash: [u8; 32],
    pub expires_at: DateTime<Utc>,
    pub sent_at: DateTime<Utc>,
    /// Sends while codes stayed valid (reset once one expired).
    pub sends: u32,
    /// Wrong entries of this code.
    pub attempts: u32,
}

/// One enrolled (or enrolling) second factor of a user.
#[derive(Clone, PartialEq, Eq)]
pub struct Factor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: MfaMethod,
    pub status: FactorStatus,
    pub label: Option<String>,
    /// TOTP only: the sealed shared secret.
    pub secret_sealed: Option<Vec<u8>>,
    /// TOTP only.
    pub totp: Option<TotpParams>,
    /// TOTP only: the last time step accepted (replay protection).
    pub last_used_step: Option<u64>,
    /// Email / SMS only: the sealed address or phone number.
    pub destination_sealed: Option<Vec<u8>>,
    /// Email / SMS only: the masked destination shown to the user.
    pub destination_hint: Option<String>,
    /// Email / SMS: a code sent to confirm enrollment or for a step-up.
    pub code: Option<PendingCode>,
    pub created_at: DateTime<Utc>,
    /// When a pending factor expires.
    pub expires_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Ready-to-insert pending factor.  The service picks the id (sealed values
/// are bound to it); the store assigns every timestamp.
#[derive(Clone)]
pub struct NewFactor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: MfaMethod,
    pub label: Option<String>,
    pub secret_sealed: Option<Vec<u8>>,
    pub totp: Option<TotpParams>,
    pub destination_sealed: Option<Vec<u8>>,
    pub destination_hint: Option<String>,
}

/// A code to store on a factor or challenge.
#[derive(Clone)]
pub struct NewCode {
    pub code_hash: [u8; 32],
    /// The factor the code was sent through (challenges only).
    pub factor_id: Uuid,
}

/// Result of storing a new code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Stored; deliver it.
    Stored { expires_at: DateTime<Utc> },
    /// The previous code was sent less than `resend_after` ago.
    TooSoon,
    /// `max_sends` codes were sent and the last one is still valid.
    LimitReached,
    /// No such factor or challenge (or it is no longer usable).
    NotFound,
}

/// A code sent for a login challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct ChallengeCode {
    pub factor_id: Uuid,
    pub code: PendingCode,
}

/// A login waiting for its second step.
#[derive(Clone, PartialEq, Eq)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Keyed hash of the token's secret part.
    pub secret_hash: [u8; 32],
    /// Who passed the password step.
    pub created_ip: IpAddr,
    pub user_agent: Option<String>,
    pub fingerprint_hash: Option<[u8; 32]>,
    /// Second-step attempts so far.
    pub attempts: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    /// The email / SMS code sent for it, if any.
    pub code: Option<ChallengeCode>,
}

/// Ready-to-insert challenge.
#[derive(Clone)]
pub struct NewChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret_hash: [u8; 32],
    pub created_ip: IpAddr,
    pub user_agent: Option<String>,
    pub fingerprint_hash: Option<[u8; 32]>,
}

/// Failed second-factor attempts of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockState {
    /// Failures in the current window.
    pub failures: u32,
    pub locked_until: Option<DateTime<Utc>>,
    /// The store's clock at read time.
    pub now: DateTime<Utc>,
}

impl LockState {
    pub fn is_locked(&self) -> bool {
        self.locked_until.is_some_and(|t| t > self.now)
    }
}

// ── What the service returns ──────────────────────────────────────────────────

/// A factor as shown to its owner — no secrets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FactorView {
    pub id: Uuid,
    pub method: MfaMethod,
    pub label: Option<String>,
    /// Email / SMS: the masked destination.
    pub destination_hint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// A user's second-factor overview.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MfaStatus {
    /// Active factors.
    pub factors: Vec<FactorView>,
    /// Whether the enforcement policy requires a second factor of them.
    pub required: bool,
    pub recovery_codes_left: u32,
    /// Methods the user may enroll (enabled by configuration).
    pub available_methods: Vec<MfaMethod>,
}

/// A started TOTP enrollment: show `otpauth_uri` as a QR code (and
/// `secret` for manual entry), then confirm with a first code.
#[derive(Clone)]
pub struct TotpEnrollment {
    pub factor_id: Uuid,
    /// Base32 (RFC 4648, no padding).
    pub secret: String,
    pub otpauth_uri: String,
    pub expires_at: DateTime<Utc>,
}

/// A started email / SMS enrollment: a code was sent to the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDelivery {
    pub factor_id: Uuid,
    pub method: MfaMethod,
    pub destination_hint: String,
    pub code_expires_at: DateTime<Utc>,
}

/// A confirmed factor.  `recovery_codes` is set when they were issued (with
/// a user's first factor) — show them once; they are stored hashed.
#[derive(Clone)]
pub struct EnrollmentConfirmed {
    pub factor: FactorView,
    pub recovery_codes: Option<Vec<String>>,
}

/// A fresh code from one of the user's active factors, required to weaken
/// their protection (remove a factor, regenerate recovery codes).
#[derive(Clone)]
pub struct StepUpProof {
    /// `totp` | `email` | `sms` | `recovery_code`.
    pub method: ProofMethod,
    pub code: String,
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for PendingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCode")
            .field("code_hash", &REDACTED)
            .field("expires_at", &self.expires_at)
            .field("sent_at", &self.sent_at)
            .field("sends", &self.sends)
            .field("attempts", &self.attempts)
            .finish()
    }
}

impl std::fmt::Debug for Factor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Factor")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("method", &self.method)
            .field("status", &self.status)
            .field("label", &self.label)
            .field(
                "secret_sealed",
                &self.secret_sealed.as_ref().map(|_| REDACTED),
            )
            .field("totp", &self.totp)
            .field("last_used_step", &self.last_used_step)
            .field("destination_hint", &self.destination_hint)
            .field("code", &self.code)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("confirmed_at", &self.confirmed_at)
            .field("last_used_at", &self.last_used_at)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewFactor")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("method", &self.method)
            .field("label", &self.label)
            .field("totp", &self.totp)
            .field("destination_hint", &self.destination_hint)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewCode")
            .field("code_hash", &REDACTED)
            .field("factor_id", &self.factor_id)
            .finish()
    }
}

impl std::fmt::Debug for ChallengeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeCode")
            .field("factor_id", &self.factor_id)
            .field("code", &self.code)
            .finish()
    }
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Challenge")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("secret_hash", &REDACTED)
            .field("created_ip", &self.created_ip)
            .field("user_agent", &self.user_agent)
            .field("attempts", &self.attempts)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewChallenge")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("created_ip", &self.created_ip)
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("factor_id", &self.factor_id)
            .field("secret", &REDACTED)
            .field("otpauth_uri", &REDACTED)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for EnrollmentConfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentConfirmed")
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

impl std::fmt::Debug for StepUpProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpProof")
            .field("method", &self.method)
            .field("code", &REDACTED)
            .finish()
    }
}
