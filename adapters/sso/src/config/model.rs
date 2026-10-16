//! z-auth-sso configuration models.

use std::collections::BTreeMap;
use std::time::Duration;

use z_auth::conf::config::Setting;
use z_auth::identity::external::ProviderPolicy;

/// Validated settings, built by [`RawSsoConfig::build`].
#[derive(Debug, Clone)]
pub struct SsoSettings {
    /// Where every provider sends the browser back (registered with each
    /// provider as the redirect URI).
    pub callback_url: String,
    /// How long a redirect to a provider stays valid.
    pub flow_ttl: Duration,
    pub providers: Vec<ProviderSettings>,
}

/// One identity provider.
#[derive(Clone)]
pub struct ProviderSettings {
    /// The provider's name in the configuration (`google`, `github`, …),
    /// recorded with every identity it links.
    pub name: String,
    /// Shown to users; defaults to the name.
    pub display_name: String,
    pub client_id: String,
    /// `None` for a public client (PKCE only).
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    /// How z-auth links and provisions this provider's identities.
    pub policy: ProviderPolicy,
    /// Pass the provider's `amr` (e.g. `mfa`) on to the session.  Only for
    /// providers whose MFA you rely on.
    pub trust_amr: bool,
    pub kind: ProviderKind,
}

/// The protocol a provider speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderKind {
    /// OpenID Connect: endpoints from discovery, a signed ID token.
    Oidc(OidcEndpoints),
    /// Plain OAuth2: an access token and a user-info endpoint.
    OAuth2(OAuth2Endpoints),
    /// GitHub (OAuth2, emails from `/user/emails`).
    GitHub(GitHubEndpoints),
}

impl ProviderKind {
    /// The `kind` setting's value.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Oidc(_) => "oidc",
            Self::OAuth2(_) => "oauth2",
            Self::GitHub(_) => "github",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcEndpoints {
    /// Exactly as the provider's tokens carry it (`iss`).
    pub issuer: String,
    /// How the client authenticates at the token endpoint; `None` lets the
    /// discovery document decide (`client_secret_basic` when listed).
    pub token_auth: Option<TokenAuth>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuth2Endpoints {
    /// Recorded as the identities' issuer (the provider has no `iss`).
    pub issuer: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub token_auth: TokenAuth,
    /// Send a PKCE challenge (S256).
    pub pkce: bool,
    pub claims: ClaimMap,
}

/// Where the user-info response keeps each field, as JSON pointers
/// (`/id`, `/emails/0/value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMap {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubEndpoints {
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub emails_url: String,
}

/// Client authentication at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// HTTP Basic (`client_secret_basic`).
    Basic,
    /// In the form body (`client_secret_post`).
    Post,
}

impl std::str::FromStr for TokenAuth {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "basic" | "client_secret_basic" => Ok(Self::Basic),
            "post" | "client_secret_post" => Ok(Self::Post),
            other => Err(format!(
                "unknown token_auth '{other}' (expected basic or post)"
            )),
        }
    }
}

// ── Raw configuration ─────────────────────────────────────────────────────────

/// Every setting as read, unvalidated.  Fields left `None` fall back to the
/// defaults in [`crate::constants`].
#[derive(Debug, Clone, Default)]
pub struct RawSsoConfig {
    pub callback_url: Option<String>,
    pub flow_ttl_secs: Option<u64>,
    pub providers: Vec<RawProvider>,
}

/// One provider's settings by name relative to the provider (`client_id`,
/// `claims.email`), each with where it came from.
#[derive(Clone, Default)]
pub struct RawProvider {
    pub name: String,
    pub settings: BTreeMap<String, Setting>,
}

impl RawSsoConfig {
    pub fn callback_url(mut self, v: impl Into<String>) -> Self {
        self.callback_url = Some(v.into());
        self
    }
    pub fn flow_ttl_secs(mut self, v: u64) -> Self {
        self.flow_ttl_secs = Some(v);
        self
    }
    /// Add a provider from `(setting, value)` pairs, e.g.
    /// `[("kind", "oidc"), ("issuer", "https://accounts.google.com")]`.
    pub fn provider<I, K, V>(mut self, name: impl Into<String>, settings: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let name = name.into();
        let settings = settings
            .into_iter()
            .map(|(k, v)| {
                let k = k.into();
                let origin = format!("sso.providers.{name}.{k}");
                (
                    k,
                    Setting {
                        value: v.into(),
                        origin,
                    },
                )
            })
            .collect();
        self.providers.push(RawProvider { name, settings });
        self
    }
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for ProviderSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSettings")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| REDACTED),
            )
            .field("scopes", &self.scopes)
            .field("policy", &self.policy)
            .field("trust_amr", &self.trust_amr)
            .field("kind", &self.kind)
            .finish()
    }
}

impl std::fmt::Debug for RawProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shown: BTreeMap<&str, &str> = self
            .settings
            .iter()
            .map(|(k, v)| {
                let value = if k == crate::constants::P_CLIENT_SECRET {
                    REDACTED
                } else {
                    v.value.as_str()
                };
                (k.as_str(), value)
            })
            .collect();
        f.debug_struct("RawProvider")
            .field("name", &self.name)
            .field("settings", &shown)
            .finish()
    }
}
