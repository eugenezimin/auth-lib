//! Account linking — external identities attached to a user, so one user
//! signs in with a password and any number of identity providers.
//!
//! A user links an identity explicitly from a recent session
//! ([`AccountLinkService`]), or a first sign-in through the identity links
//! it as the provider's [`ProviderPolicy`] allows
//! ([`login_external`](crate::security::authentication::AuthenticationService::login_external)).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

use crate::identity::external::{
    ExternalIdentity, ExternalIdentityEvents, ExternalIdentityRepository, ExternalPrincipal,
    NewExternalIdentity, ProviderPolicy,
};
use crate::identity::user::repository::UserRepository;
use crate::security::authentication::flow::FlowStateRepository;
use crate::security::session::{SessionRepository, SessionStatus};
use crate::utils::clock::Clock;
use crate::utils::error::AuthError;

/// The storage external sign-in and linking need, passed to
/// [`ZAuthBuilder::external_identities`](crate::ZAuthBuilder::external_identities).
#[derive(Clone)]
pub struct ExternalStores {
    pub identities: Arc<dyn ExternalIdentityRepository>,
    pub flows: Arc<dyn FlowStateRepository>,
    pub events: Arc<dyn ExternalIdentityEvents>,
}

/// Explicit linking from a signed-in session.
///
/// Every change needs a recent session: one opened at most
/// `AUTH_EXTERNAL_LINK_MAX_AUTH_AGE_SECS` ago (refreshing does not renew
/// it), so a stolen long-lived session cannot add a sign-in method.
#[async_trait]
pub trait AccountLinkService: Send + Sync {
    /// Check that session `session_id` may link or unlink now — active,
    /// recent, its user active — and return its user.  A protocol adapter
    /// calls it before sending the user to the identity provider.
    async fn authorize(&self, session_id: Uuid) -> Result<Uuid, AuthError>;

    /// Link `principal` to the user of session `session_id` (checked as by
    /// [`authorize`](Self::authorize)).  Linking an identity the user
    /// already has returns it unchanged.
    ///
    /// # Errors
    /// [`AuthError::ExternalIdentityLinkedElsewhere`],
    /// [`AuthError::ProviderAlreadyLinked`],
    /// [`AuthError::ReauthenticationRequired`].
    async fn link(
        &self,
        session_id: Uuid,
        principal: &ExternalPrincipal,
        policy: &ProviderPolicy,
    ) -> Result<ExternalIdentity, AuthError>;

    /// Remove one of the session user's identities and return it.
    ///
    /// # Errors
    /// [`AuthError::LastLoginMethod`] when the user has no password and no
    /// other identity; [`AuthError::ExternalIdentityNotFound`].
    async fn unlink(
        &self,
        session_id: Uuid,
        identity_id: Uuid,
    ) -> Result<ExternalIdentity, AuthError>;

    /// A user's identities, oldest first.
    async fn list(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, AuthError>;
}

/// Default implementation of [`AccountLinkService`].
pub struct AccountLinkServiceImpl {
    users: Arc<dyn UserRepository>,
    sessions: Arc<dyn SessionRepository>,
    linker: Option<Linker>,
    clock: Arc<dyn Clock>,
    max_auth_age: Duration,
}

impl AccountLinkServiceImpl {
    /// Without `stores` every call fails with [`AuthError::Config`].
    pub fn new(
        users: Arc<dyn UserRepository>,
        sessions: Arc<dyn SessionRepository>,
        stores: Option<ExternalStores>,
        clock: Arc<dyn Clock>,
        max_auth_age: Duration,
    ) -> Self {
        Self {
            users,
            sessions,
            linker: stores.map(|s| Linker::new(&s)),
            clock,
            max_auth_age,
        }
    }

    fn linker(&self) -> Result<&Linker, AuthError> {
        self.linker.as_ref().ok_or_else(missing_stores)
    }
}

#[async_trait]
impl AccountLinkService for AccountLinkServiceImpl {
    async fn authorize(&self, session_id: Uuid) -> Result<Uuid, AuthError> {
        self.linker()?;
        let session = self
            .sessions
            .find(session_id)
            .await?
            .ok_or(AuthError::TokenRevoked)?;
        if session.status != SessionStatus::Active {
            return Err(AuthError::TokenRevoked);
        }
        let now = self.clock.now();
        if now >= session.idle_expires_at || now >= session.absolute_expires_at {
            return Err(AuthError::SessionExpired);
        }
        let age = (now - session.created_at).to_std().unwrap_or_default();
        if age > self.max_auth_age {
            return Err(AuthError::ReauthenticationRequired);
        }
        match self.users.is_active(session.user_id).await? {
            Some(true) => Ok(session.user_id),
            Some(false) => Err(AuthError::AccountDisabled),
            None => Err(AuthError::UserNotFound),
        }
    }

    async fn link(
        &self,
        session_id: Uuid,
        principal: &ExternalPrincipal,
        policy: &ProviderPolicy,
    ) -> Result<ExternalIdentity, AuthError> {
        principal.validate()?;
        let user_id = self.authorize(session_id).await?;
        self.linker()?
            .link(user_id, principal, policy.max_links)
            .await
    }

    async fn unlink(
        &self,
        session_id: Uuid,
        identity_id: Uuid,
    ) -> Result<ExternalIdentity, AuthError> {
        let user_id = self.authorize(session_id).await?;
        let linker = self.linker()?;
        let identities = linker.identities.list_for_user(user_id).await?;
        let identity = identities
            .iter()
            .find(|i| i.id == identity_id)
            .cloned()
            .ok_or(AuthError::ExternalIdentityNotFound)?;
        let has_password = self
            .users
            .find_by_id(user_id)
            .await?
            .is_some_and(|u| u.password_hash.is_some());
        if !has_password && identities.len() < 2 {
            return Err(AuthError::LastLoginMethod);
        }
        if !linker.identities.delete(identity.id).await? {
            return Err(AuthError::ExternalIdentityNotFound);
        }
        linker.events.unlinked(&identity).await;
        Ok(identity)
    }

    async fn list(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, AuthError> {
        self.linker()?.identities.list_for_user(user_id).await
    }
}

pub(crate) fn missing_stores() -> AuthError {
    AuthError::Config(
        "missing adapter: external identities (ZAuthBuilder::external_identities)".into(),
    )
}

// ── Shared by every way of linking ────────────────────────────────────────────

/// Creates links: one owner per identity, at most `max_links` per provider
/// and user, and an event for each new link.
#[derive(Clone)]
pub(crate) struct Linker {
    pub identities: Arc<dyn ExternalIdentityRepository>,
    pub events: Arc<dyn ExternalIdentityEvents>,
}

impl Linker {
    pub fn new(stores: &ExternalStores) -> Self {
        Self {
            identities: stores.identities.clone(),
            events: stores.events.clone(),
        }
    }

    /// Link `principal` to `user_id`; an identity already linked to this
    /// user is returned unchanged.
    pub async fn link(
        &self,
        user_id: Uuid,
        principal: &ExternalPrincipal,
        max_links: u32,
    ) -> Result<ExternalIdentity, AuthError> {
        if let Some(existing) = self
            .identities
            .find_by_subject(&principal.issuer, &principal.subject)
            .await?
        {
            return if existing.user_id == user_id {
                Ok(existing)
            } else {
                Err(AuthError::ExternalIdentityLinkedElsewhere)
            };
        }
        if max_links > 0 {
            let linked = self.identities.list_for_user(user_id).await?;
            let same_provider = linked
                .iter()
                .filter(|i| i.provider == principal.provider)
                .count();
            if same_provider >= max_links as usize {
                return Err(AuthError::ProviderAlreadyLinked);
            }
        }
        let identity = self
            .identities
            .create(NewExternalIdentity::for_principal(user_id, principal))
            .await?;
        self.events.linked(&identity).await;
        Ok(identity)
    }
}

/// Authentication methods kept from a provider: RFC 8176-shaped values
/// only (they are stored comma-separated).
pub(crate) fn clean_amr(amr: &[String]) -> impl Iterator<Item = String> + '_ {
    amr.iter()
        .filter(|m| {
            !m.is_empty()
                && m.len() <= 32
                && m.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .cloned()
}

/// A sign-in waiting for the password of the account it would be linked
/// to, as stored in the flow state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingLink {
    pub user_id: Uuid,
    pub max_links: u32,
    /// Provider, issuer, subject, email and `amr` of the identity.
    pub principal: ExternalPrincipal,
}

impl PendingLink {
    /// Each field base64url-encoded, joined with `.`.
    pub fn encode(&self) -> String {
        let p = &self.principal;
        [
            self.user_id.to_string(),
            self.max_links.to_string(),
            p.provider.clone(),
            p.issuer.clone(),
            p.subject.clone(),
            p.email.clone().unwrap_or_default(),
            p.amr.join(","),
        ]
        .iter()
        .map(|f| URL_SAFE_NO_PAD.encode(f))
        .collect::<Vec<_>>()
        .join(".")
    }

    pub fn decode(value: &str) -> Result<Self, AuthError> {
        let bad = || AuthError::Internal("malformed pending link".into());
        let fields = value
            .split('.')
            .map(|f| {
                URL_SAFE_NO_PAD
                    .decode(f)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(bad)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let [user_id, max_links, provider, issuer, subject, email, amr] =
            <[String; 7]>::try_from(fields).map_err(|_| bad())?;
        let mut principal = ExternalPrincipal::new(provider, issuer, subject);
        principal.email = Some(email).filter(|e| !e.is_empty());
        principal.amr = amr
            .split(',')
            .filter(|m| !m.is_empty())
            .map(Into::into)
            .collect();
        Ok(Self {
            user_id: user_id.parse().map_err(|_| bad())?,
            max_links: max_links.parse().map_err(|_| bad())?,
            principal,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_links_round_trip() {
        let mut principal =
            ExternalPrincipal::new("google", "https://accounts.google.com", "1.2|3")
                .with_email("a.b@example.com", true);
        principal.amr = vec!["pwd".into(), "mfa".into()];
        let pending = PendingLink {
            user_id: Uuid::new_v4(),
            max_links: 1,
            principal,
        };
        let decoded = PendingLink::decode(&pending.encode()).unwrap();
        // `email_verified` is not kept: confirming needs the password anyway.
        assert!(!decoded.principal.email_verified);
        assert_eq!(decoded.user_id, pending.user_id);
        assert_eq!(decoded.principal.subject, "1.2|3");
        assert_eq!(decoded.principal.email.as_deref(), Some("a.b@example.com"));
        assert_eq!(decoded.principal.amr, ["pwd", "mfa"]);
    }

    #[test]
    fn malformed_pending_links_are_rejected() {
        assert!(PendingLink::decode("").is_err());
        assert!(PendingLink::decode("a.b.c").is_err());
    }

    #[test]
    fn only_token_shaped_methods_are_kept() {
        let amr = vec!["pwd".into(), "a,b".into(), String::new(), "hwk".into()];
        assert_eq!(clean_amr(&amr).collect::<Vec<_>>(), ["pwd", "hwk"]);
    }
}
