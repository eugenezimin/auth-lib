//! Framework-agnostic endpoints, in the style of z-auth's
//! `controller::api::handlers`: the host wraps them in its web framework,
//! sets the binding cookie and supplies the [`ClientContext`].
//!
//! ```rust,ignore
//! // axum (host application code)
//! async fn sso_start(State(app): State<App>, Path(provider): Path<String>, jar: CookieJar)
//!     -> Result<(CookieJar, Redirect), MyError> {
//!     let r = api::begin_login(&app.sso, &app.auth, &provider).await?;
//!     let cookie = Cookie::build(("sso_binding", r.binding)).http_only(true).secure(true)
//!         .same_site(SameSite::Lax).path("/auth/sso");
//!     Ok((jar.add(cookie), Redirect::to(&r.url)))
//! }
//! async fn sso_callback(State(app): State<App>, Query(q): Query<CallbackRequest>,
//!     jar: CookieJar, ConnectInfo(addr): ConnectInfo<SocketAddr>)
//!     -> Result<Json<CallbackResponse>, MyError> {
//!     let binding = jar.get("sso_binding").map(|c| c.value().to_owned()).unwrap_or_default();
//!     Ok(Json(api::callback(&app.sso, &app.auth, q, &binding, ClientContext::new(addr.ip())).await?))
//! }
//! ```

use chrono::{DateTime, Utc};
use z_auth::ZAuth;
use z_auth::controller::api::ApiError;
use z_auth::controller::api::dto::{
    ExternalIdentityResponse, LinkChallengeResponse, LoginChallengeResponse, TokenPairResponse,
};
use z_auth::security::authentication::{ClientContext, ExternalLoginOutcome};

use crate::service::{CallbackOutcome, CallbackParams, ProviderInfo, Redirect, Sso};

/// A provider a sign-in page may offer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderResponse {
    pub name: String,
    pub display_name: String,
}

/// Response of the endpoints that start a redirect.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RedirectResponse {
    /// Send the browser here.
    pub url: String,
    /// Store in an HttpOnly cookie for the callback; never expose to
    /// scripts.
    pub binding: String,
    pub expires_at: DateTime<Utc>,
}

/// The callback's query string.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CallbackRequest {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Response of the callback.
///
/// JSON: `{"status": "authenticated", …}`, `{"status":
/// "second_factor_required", …}`, `{"status": "link_confirmation_required",
/// …}` (then `POST /login/link`), or `{"status": "linked", "id": …,
/// "provider": …}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CallbackResponse {
    Authenticated(TokenPairResponse),
    SecondFactorRequired(LoginChallengeResponse),
    LinkConfirmationRequired(LinkChallengeResponse),
    Linked(ExternalIdentityResponse),
}

/// `GET /auth/sso/providers`
pub fn providers(sso: &Sso) -> Vec<ProviderResponse> {
    sso.providers().into_iter().map(Into::into).collect()
}

/// `GET /auth/sso/{provider}/start` — then redirect the browser.
pub async fn begin_login(
    sso: &Sso,
    auth: &ZAuth,
    provider: &str,
) -> Result<RedirectResponse, ApiError> {
    Ok(sso.begin_login(auth, provider).await?.into())
}

/// `POST /me/identities/{provider}` with a bearer token of a recent
/// session — then redirect the browser.
pub async fn begin_link(
    sso: &Sso,
    auth: &ZAuth,
    bearer: &str,
    provider: &str,
) -> Result<RedirectResponse, ApiError> {
    Ok(sso.begin_link(auth, bearer, provider).await?.into())
}

/// `GET /auth/sso/callback` — the provider's redirect back.
pub async fn callback(
    sso: &Sso,
    auth: &ZAuth,
    req: CallbackRequest,
    binding: &str,
    ctx: ClientContext,
) -> Result<CallbackResponse, ApiError> {
    Ok(sso.callback(auth, req.into(), binding, ctx).await?.into())
}

impl From<ProviderInfo> for ProviderResponse {
    fn from(p: ProviderInfo) -> Self {
        Self {
            name: p.name,
            display_name: p.display_name,
        }
    }
}

impl From<Redirect> for RedirectResponse {
    fn from(r: Redirect) -> Self {
        Self {
            url: r.url,
            binding: r.binding,
            expires_at: r.expires_at,
        }
    }
}

impl From<CallbackRequest> for CallbackParams {
    fn from(r: CallbackRequest) -> Self {
        Self {
            state: r.state,
            code: r.code,
            error: r.error,
            error_description: r.error_description,
        }
    }
}

impl From<CallbackOutcome> for CallbackResponse {
    fn from(o: CallbackOutcome) -> Self {
        match o {
            CallbackOutcome::Login(ExternalLoginOutcome::Tokens(pair)) => {
                Self::Authenticated(pair.into())
            }
            CallbackOutcome::Login(ExternalLoginOutcome::SecondFactor(c)) => {
                Self::SecondFactorRequired(c.into())
            }
            CallbackOutcome::Login(ExternalLoginOutcome::LinkConfirmation(c)) => {
                Self::LinkConfirmationRequired(c.into())
            }
            CallbackOutcome::Linked(identity) => Self::Linked(identity.into()),
        }
    }
}

impl std::fmt::Debug for RedirectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedirectResponse")
            .field("url", &self.url)
            .field("binding", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
