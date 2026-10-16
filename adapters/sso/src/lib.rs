//! # z-auth-sso
//!
//! Single sign-on for [z-auth](z_auth): users sign in with an identity
//! provider — Google, LinkedIn, Microsoft Entra ID, Okta, Auth0, Keycloak,
//! GitHub, Facebook, … — and z-auth issues its own session, linked to
//! their z-auth user.
//!
//! ```rust,ignore
//! use z_auth_sso::{Sso, config::{SsoConfigLoader, SsoSourceLoader}};
//!
//! let source = ConfigSource::standard()?;            // the `sso` section + AUTH_SSO_*
//! let sso = Sso::new(SsoSourceLoader::new(source.clone()).load_settings()?)?;
//! let auth = ZAuth::builder(config, repos)
//!     .external_identities(identities, flow_states)   // e.g. z-auth-postgres
//!     .build()?;
//!
//! // GET /auth/sso/google/start
//! let redirect = sso.begin_login(&auth, "google").await?;
//! // → set redirect.binding as an HttpOnly cookie, send the browser to redirect.url
//!
//! // GET /auth/sso/callback?state=…&code=…
//! match sso.callback(&auth, params, &binding_cookie, ctx).await? {
//!     CallbackOutcome::Login(ExternalLoginOutcome::Tokens(pair)) => { /* signed in */ }
//!     CallbackOutcome::Login(ExternalLoginOutcome::SecondFactor(c)) => { /* complete_login */ }
//!     CallbackOutcome::Login(ExternalLoginOutcome::LinkConfirmation(c)) => { /* confirm_link */ }
//!     CallbackOutcome::Linked(identity) => { /* from begin_link */ }
//! }
//! ```
//!
//! ## Providers
//!
//! Each provider is a mapping under `sso.providers.<name>`, its `kind`
//! choosing the protocol:
//!
//! - `oidc` *(feature `oidc`, default)* — any OpenID Connect provider:
//!   only the issuer is configured, the rest comes from discovery.
//! - `oauth2` — any plain OAuth2 provider with a user-info endpoint
//!   (Facebook, Discord, …): endpoints and a JSON-pointer claim mapping.
//! - `github` *(feature `github`)* — GitHub, whose verified emails come
//!   from its own API.
//!
//! Anything else implements [`IdentityProvider`] in the host and joins
//! with [`Sso::with_provider`].
//!
//! ## What z-auth does with the identity
//!
//! Every provider ends in z-auth's
//! [`login_external`](z_auth::security::authentication::AuthenticationService::login_external):
//! identities are linked to users by issuer and subject, a first sign-in
//! links by email only as the provider's policy allows (`link`,
//! `provisioning`, `trust_email`), and the user's second factor still
//! applies.  [`Sso::begin_link`] links an identity to a signed-in user
//! instead.
//!
//! ## Security
//!
//! - Authorization code flow with PKCE (S256), a fresh `state` and nonce
//!   per redirect, each accepted once and only within `sso.flow_ttl_secs`.
//! - The callback must come from the browser that started it
//!   ([`Redirect::binding`]).
//! - ID tokens: asymmetric signatures from the provider's JWKS only;
//!   issuer, audience, `azp`, expiry and nonce checked.
//! - Only `https` endpoints (plain `http` on localhost, for development).

pub mod api;
pub mod config;
pub mod constants;
mod flow;
mod http;
pub mod provider;
mod service;

pub use provider::{AuthorizationRequest, IdentityProvider};
pub use service::{CallbackOutcome, CallbackParams, ProviderInfo, Redirect, Sso};
