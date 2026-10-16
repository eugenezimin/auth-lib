//! External identities — users as asserted by another identity provider
//! (OIDC, OAuth2, SAML, a directory), and their links to z-auth users.
//!
//! Protocol adapters such as z-auth-sso verify the provider's assertion and
//! hand z-auth an [`ExternalPrincipal`]; signing in with it and linking it
//! live in [`crate::security::authentication`].

pub mod events;
pub mod model;
pub mod repository;

pub use events::{ExternalIdentityEvents, NoopExternalIdentityEvents};
pub use model::{
    ExternalIdentity, ExternalPrincipal, LinkPolicy, NewExternalIdentity, ProviderPolicy,
    Provisioning,
};
pub use repository::ExternalIdentityRepository;
