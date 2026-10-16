//! z-auth-sso configuration: the `sso` section of the configuration file
//! and `AUTH_SSO_*` variables.

pub mod loaders;
pub mod model;

pub use loaders::{SsoConfigLoader, SsoDirectLoader, SsoEnvLoader, SsoSourceLoader, provider_env};
pub use model::{
    ClaimMap, GitHubEndpoints, OAuth2Endpoints, OidcEndpoints, ProviderKind, ProviderSettings,
    RawProvider, RawSsoConfig, SsoSettings, TokenAuth,
};
