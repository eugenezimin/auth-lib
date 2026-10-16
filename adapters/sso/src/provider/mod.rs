//! Identity providers: the [`IdentityProvider`] port and its built-in
//! implementations, one per configured `kind`.
//!
//! | kind     | type               | protocol                                     |
//! |----------|--------------------|----------------------------------------------|
//! | `oidc`   | [`OidcProvider`]   | OpenID Connect: discovery, signed ID token   |
//! | `oauth2` | [`OAuth2Provider`] | OAuth2 + a user-info endpoint, claims mapped |
//! | `github` | [`OAuth2Provider`] | the GitHub preset (verified emails from its API) |
//!
//! A host adds anything else by implementing [`IdentityProvider`] and
//! registering it with [`Sso::with_provider`](crate::Sso::with_provider).

use std::sync::Arc;

use async_trait::async_trait;
use z_auth::AuthError;
use z_auth::identity::external::{ExternalPrincipal, ProviderPolicy};

use crate::config::{ProviderKind, ProviderSettings};

mod oauth2;
#[cfg(feature = "oidc")]
mod oidc;

pub use oauth2::OAuth2Provider;
#[cfg(feature = "oidc")]
pub use oidc::OidcProvider;

/// One redirect to a provider: what the authorization request carried and
/// the callback must match.
#[derive(Clone, Copy)]
pub struct AuthorizationRequest<'a> {
    pub redirect_uri: &'a str,
    pub state: &'a str,
    /// OIDC nonce; providers without ID tokens ignore it.
    pub nonce: &'a str,
    /// PKCE code verifier; the challenge sent is its S256.
    pub pkce_verifier: &'a str,
}

/// An identity provider: where to send the browser, and how to turn the
/// code it returns into a verified [`ExternalPrincipal`].
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// The provider's name (`google`), unique per [`Sso`](crate::Sso).
    fn name(&self) -> &str;

    /// Shown to users.
    fn display_name(&self) -> &str {
        self.name()
    }

    /// How z-auth links and provisions this provider's identities.
    fn policy(&self) -> ProviderPolicy;

    /// The URL to send the browser to.
    async fn authorization_url(
        &self,
        request: AuthorizationRequest<'_>,
    ) -> Result<String, AuthError>;

    /// Redeem the authorization `code` and verify who signed in.  Only
    /// fields the provider vouched for may be set in the principal.
    async fn exchange(
        &self,
        code: &str,
        request: AuthorizationRequest<'_>,
    ) -> Result<ExternalPrincipal, AuthError>;
}

/// The built-in provider for one configured provider.
pub fn build(
    settings: ProviderSettings,
    http: reqwest::Client,
) -> Result<Arc<dyn IdentityProvider>, AuthError> {
    Ok(match &settings.kind {
        #[cfg(feature = "oidc")]
        ProviderKind::Oidc(_) => Arc::new(OidcProvider::new(settings, http)),
        #[cfg(not(feature = "oidc"))]
        ProviderKind::Oidc(_) => {
            return Err(AuthError::Config(
                "kind `oidc` needs z-auth-sso's `oidc` feature".into(),
            ));
        }
        ProviderKind::OAuth2(_) | ProviderKind::GitHub(_) => {
            Arc::new(OAuth2Provider::new(settings, http))
        }
    })
}

/// `endpoint` with the query parameters appended.
pub(crate) fn with_query(endpoint: &str, params: &[(&str, &str)]) -> Result<String, AuthError> {
    let mut url = reqwest::Url::parse(endpoint)
        .map_err(|e| AuthError::Config(format!("invalid endpoint {endpoint}: {e}")))?;
    {
        let mut query = url.query_pairs_mut();
        for (k, v) in params {
            query.append_pair(k, v);
        }
    }
    Ok(url.into())
}
