//! External identity models.
//!
//! Contains **only** plain data structures.
//! - Persistence contract → [`crate::identity::external::repository`]
//! - Login and linking    → [`crate::security::authentication`]

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::utils::error::AuthError;

// ── Verified assertion ────────────────────────────────────────────────────────

/// A user as asserted by an external identity provider, once the protocol
/// adapter (e.g. z-auth-sso) has verified the assertion.  z-auth trusts
/// every field, so an adapter must only fill in what it verified.
///
/// The user is identified by `(issuer, subject)` alone; `email` is only a
/// hint for linking to an existing account (see [`LinkPolicy`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalPrincipal {
    /// The host's name for the provider configuration (`google`, `github`).
    pub provider: String,
    /// The provider's issuer: OIDC `iss`, or a fixed URL for plain OAuth2.
    pub issuer: String,
    /// The provider's stable id of the user (OIDC `sub`).
    pub subject: String,
    pub email: Option<String>,
    /// The provider vouches that the user controls `email`.  Acted on only
    /// for providers trusted with emails ([`ProviderPolicy::trust_email`]).
    pub email_verified: bool,
    /// Suggested username for a provisioned user; dropped when taken.
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    /// Authentication methods the provider reports (RFC 8176), only from a
    /// provider trusted to report them.  `mfa` satisfies z-auth's second
    /// factor.
    pub amr: Vec<String>,
}

impl ExternalPrincipal {
    /// A principal with only its identity set.
    pub fn new(
        provider: impl Into<String>,
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            issuer: issuer.into(),
            subject: subject.into(),
            email: None,
            email_verified: false,
            username: None,
            first_name: None,
            last_name: None,
            amr: Vec::new(),
        }
    }

    pub fn with_email(mut self, email: impl Into<String>, verified: bool) -> Self {
        self.email = Some(email.into());
        self.email_verified = verified;
        self
    }

    /// Rejects a principal without a provider, issuer or subject.
    pub fn validate(&self) -> Result<(), AuthError> {
        for (field, value) in [
            ("provider", &self.provider),
            ("issuer", &self.issuer),
            ("subject", &self.subject),
        ] {
            if value.trim().is_empty() {
                return Err(AuthError::ExternalLoginFailed(format!(
                    "the external identity has no {field}"
                )));
            }
        }
        Ok(())
    }
}

// ── Persisted entity ──────────────────────────────────────────────────────────

/// An external identity linked to a user.  A user may have many; an
/// `(issuer, subject)` pair belongs to at most one user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    /// The email the provider reported when the identity was linked.
    pub email: Option<String>,
    /// When the identity was linked.
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Ready-to-insert link, consumed by
/// [`ExternalIdentityRepository::create`](crate::identity::external::ExternalIdentityRepository::create).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewExternalIdentity {
    pub user_id: Uuid,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
}

impl NewExternalIdentity {
    pub fn for_principal(user_id: Uuid, principal: &ExternalPrincipal) -> Self {
        Self {
            user_id,
            provider: principal.provider.clone(),
            issuer: principal.issuer.clone(),
            subject: principal.subject.clone(),
            email: principal.email.clone(),
        }
    }
}

// ── Per-provider policy ───────────────────────────────────────────────────────

/// What happens at a first sign-in through an identity that is not linked
/// yet, when a user with the provider's email already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkPolicy {
    /// Refuse; the user signs in and links the identity explicitly.
    Never,
    /// Ask for the existing account's password (and second factor), then
    /// link.
    #[default]
    ConfirmWithPassword,
    /// Link without asking when the provider is trusted with emails, says
    /// the email is verified and the existing account's email is verified
    /// too; otherwise ask for the password as `ConfirmWithPassword` does.
    VerifiedEmail,
}

/// What happens at a first sign-in through an identity that is not linked
/// yet, when no user has the provider's email.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Provisioning {
    /// Refuse: only existing users may sign in.
    #[default]
    Deny,
    /// Create a user without a password and link the identity.
    Create,
}

/// How z-auth treats one identity provider.  Supplied by the protocol
/// adapter (e.g. from its configuration) with every sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderPolicy {
    pub link: LinkPolicy,
    pub provisioning: Provisioning,
    /// The provider's `email_verified` can be relied on.  Off for providers
    /// that let users enter unverified addresses.
    pub trust_email: bool,
    /// Identities of this provider one user may link; 0 means unlimited.
    pub max_links: u32,
}

impl Default for ProviderPolicy {
    fn default() -> Self {
        Self {
            link: LinkPolicy::default(),
            provisioning: Provisioning::default(),
            trust_email: false,
            max_links: 1,
        }
    }
}

impl std::str::FromStr for LinkPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "never" => Ok(Self::Never),
            "confirm_with_password" => Ok(Self::ConfirmWithPassword),
            "verified_email" => Ok(Self::VerifiedEmail),
            other => Err(format!(
                "unknown link policy '{other}' (expected never, confirm_with_password \
                 or verified_email)"
            )),
        }
    }
}

impl std::str::FromStr for Provisioning {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "deny" => Ok(Self::Deny),
            "create" => Ok(Self::Create),
            other => Err(format!(
                "unknown provisioning '{other}' (expected deny or create)"
            )),
        }
    }
}
