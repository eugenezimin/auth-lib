//! [`Sso`] — sends users to their identity provider and signs them in (or
//! links the identity) when the provider sends them back.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use z_auth::AuthError;
use z_auth::ZAuth;
use z_auth::identity::external::ExternalIdentity;
use z_auth::security::authentication::{ClientContext, ExternalLoginOutcome, flow_key};

use crate::config::SsoSettings;
use crate::constants::FLOW_SSO;
use crate::flow::{Intent, PendingRedirect};
use crate::http::{default_client, failed, random_secret, sha256_b64};
use crate::provider::{self, AuthorizationRequest, IdentityProvider};

/// Where to send the browser, and the secret that ties the callback to it.
#[derive(Clone)]
pub struct Redirect {
    /// The provider's authorization URL.
    pub url: String,
    /// Keep in an HttpOnly, `SameSite=Lax` cookie until the callback and
    /// pass it to [`Sso::callback`]: a callback in any other browser is
    /// refused, so nobody can sign a victim into the attacker's account.
    pub binding: String,
    /// When the redirect stops being accepted (the cookie's lifetime).
    pub expires_at: DateTime<Utc>,
}

/// The query of the provider's redirect back to the callback URL.
#[derive(Debug, Clone, Default)]
pub struct CallbackParams {
    pub state: Option<String>,
    pub code: Option<String>,
    /// Set when the user declined or the provider failed.
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// What a callback did.
#[derive(Debug, Clone)]
pub enum CallbackOutcome {
    /// A sign-in: tokens, a second-factor challenge, or a request for the
    /// existing account's password.
    Login(ExternalLoginOutcome),
    /// The identity was linked to the signed-in user who asked for it.
    Linked(ExternalIdentity),
}

/// A configured provider, for a sign-in page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInfo {
    pub name: String,
    pub display_name: String,
}

/// Single sign-on through the configured identity providers.
///
/// It keeps no state of its own: redirects wait in the flow-state store of
/// the [`ZAuth`] passed to each call (see
/// [`ZAuthBuilder::external_identities`](z_auth::ZAuthBuilder::external_identities)),
/// so any instance may serve the callback.
pub struct Sso {
    callback_url: String,
    flow_ttl: Duration,
    providers: BTreeMap<String, Arc<dyn IdentityProvider>>,
}

impl Sso {
    /// The configured providers over a default HTTP client.
    pub fn new(settings: SsoSettings) -> Result<Self, AuthError> {
        Self::with_http_client(settings, default_client()?)
    }

    /// The configured providers over `http` (e.g. with a proxy).
    pub fn with_http_client(
        settings: SsoSettings,
        http: reqwest::Client,
    ) -> Result<Self, AuthError> {
        let mut providers = BTreeMap::new();
        for p in settings.providers {
            providers.insert(p.name.clone(), provider::build(p, http.clone())?);
        }
        Ok(Self {
            callback_url: settings.callback_url,
            flow_ttl: settings.flow_ttl,
            providers,
        })
    }

    /// Add (or replace, by name) a provider the host implemented.
    pub fn with_provider(mut self, provider: Arc<dyn IdentityProvider>) -> Self {
        self.providers.insert(provider.name().to_string(), provider);
        self
    }

    /// Every provider, by name.
    pub fn providers(&self) -> Vec<ProviderInfo> {
        self.providers
            .values()
            .map(|p| ProviderInfo {
                name: p.name().to_string(),
                display_name: p.display_name().to_string(),
            })
            .collect()
    }

    fn provider(&self, name: &str) -> Result<&Arc<dyn IdentityProvider>, AuthError> {
        self.providers
            .get(name)
            .ok_or_else(|| AuthError::UnknownProvider(name.to_string()))
    }

    /// Start signing in with `provider`: send the browser to
    /// [`Redirect::url`].
    pub async fn begin_login(&self, auth: &ZAuth, provider: &str) -> Result<Redirect, AuthError> {
        self.begin(auth, provider, Intent::Login).await
    }

    /// Start linking `provider` to the user of the bearer token.  The
    /// session must be recent (`AUTH_EXTERNAL_LINK_MAX_AUTH_AGE_SECS`);
    /// otherwise [`AuthError::ReauthenticationRequired`] before anything
    /// is sent.
    pub async fn begin_link(
        &self,
        auth: &ZAuth,
        bearer: &str,
        provider: &str,
    ) -> Result<Redirect, AuthError> {
        let claims = auth.authentication().verify_access_token(bearer).await?;
        auth.account_links().authorize(claims.sid).await?;
        self.begin(
            auth,
            provider,
            Intent::Link {
                session_id: claims.sid,
            },
        )
        .await
    }

    async fn begin(
        &self,
        auth: &ZAuth,
        provider: &str,
        intent: Intent,
    ) -> Result<Redirect, AuthError> {
        let idp = self.provider(provider)?;
        let flows = flow_store(auth)?;
        let state = random_secret()?;
        let binding = random_secret()?;
        let pending = PendingRedirect {
            intent,
            provider: provider.to_string(),
            nonce: random_secret()?,
            pkce_verifier: random_secret()?,
            binding_hash: sha256_b64(&binding),
        };
        let url = idp
            .authorization_url(AuthorizationRequest {
                redirect_uri: &self.callback_url,
                state: &state,
                nonce: &pending.nonce,
                pkce_verifier: &pending.pkce_verifier,
            })
            .await?;
        flows
            .put(
                &flow_key(FLOW_SSO, &state),
                &pending.encode(),
                self.flow_ttl,
            )
            .await?;
        Ok(Redirect {
            url,
            binding,
            expires_at: Utc::now() + self.flow_ttl,
        })
    }

    /// Finish at the callback URL: `params` from its query, `binding` from
    /// the cookie set with the [`Redirect`].  Each redirect is accepted
    /// once.
    ///
    /// # Errors
    /// [`AuthError::ChallengeExpired`] for an unknown, used or expired
    /// `state`; [`AuthError::ExternalLoginFailed`] when the binding does
    /// not match or the provider's answer is refused;
    /// [`AuthError::ExternalProviderUnavailable`] when it cannot be reached.
    pub async fn callback(
        &self,
        auth: &ZAuth,
        params: CallbackParams,
        binding: &str,
        ctx: ClientContext,
    ) -> Result<CallbackOutcome, AuthError> {
        let flows = flow_store(auth)?;
        let state = params
            .state
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| failed("the callback has no state"))?;
        let pending = flows
            .take(&flow_key(FLOW_SSO, state))
            .await?
            .ok_or(AuthError::ChallengeExpired)?;
        let pending = PendingRedirect::decode(&pending)?;
        if sha256_b64(binding) != pending.binding_hash {
            return Err(failed("the sign-in was started in another browser"));
        }
        if let Some(error) = &params.error {
            let detail = params.error_description.as_deref().unwrap_or_default();
            return Err(failed(format!("the provider reported {error} {detail}")));
        }
        let code = params
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| failed("the callback has no code"))?;

        let idp = self.provider(&pending.provider)?;
        let mut principal = idp
            .exchange(
                code,
                AuthorizationRequest {
                    redirect_uri: &self.callback_url,
                    state,
                    nonce: &pending.nonce,
                    pkce_verifier: &pending.pkce_verifier,
                },
            )
            .await?;
        // Whatever a host provider reports, record it under its own name.
        principal.provider = idp.name().to_string();
        match pending.intent {
            Intent::Login => Ok(CallbackOutcome::Login(
                auth.authentication()
                    .login_external(principal, idp.policy(), ctx)
                    .await?,
            )),
            Intent::Link { session_id } => Ok(CallbackOutcome::Linked(
                auth.account_links()
                    .link(session_id, &principal, &idp.policy())
                    .await?,
            )),
        }
    }
}

fn flow_store(
    auth: &ZAuth,
) -> Result<&Arc<dyn z_auth::security::authentication::FlowStateRepository>, AuthError> {
    auth.flow_states().ok_or_else(|| {
        AuthError::Config(
            "z-auth-sso needs ZAuthBuilder::external_identities (the flow-state store)".into(),
        )
    })
}
