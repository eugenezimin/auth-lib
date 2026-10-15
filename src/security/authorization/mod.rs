//! Authorization context — permission catalog, grants, token claims and
//! request-time checks.
//!
//! The model is chosen by `AUTH_AUTHZ_MODE` ([`AuthzMode`](crate::conf::config::AuthzMode)):
//! `none`, `rbac` (roles, see [`crate::identity::access`]), `permissions`, or
//! `combined` (roles bundle permissions).  Authorization data travels inside
//! access tokens, so checks need no storage access; it is re-read at login /
//! refresh only.  Token format: `docs/authorization.md`.

pub mod catalog;
pub mod codec;
pub mod events;
pub mod model;
pub mod repository;
pub mod service;
pub mod service_impl;
pub mod validation;

pub use catalog::CatalogCache;
pub use codec::{BitsetPermissionCodec, PermissionCodec};
pub use events::CatalogEvents;
pub use model::{
    EffectiveGrants, EffectivePermissions, GrantView, NewPermission, Permission,
    PermissionAssignment, PermissionCatalog, PermissionGrant, PermissionKind, PermissionOption,
    PermissionValue,
};
pub use repository::PermissionRepository;
pub use service::{Authorizer, AuthzClaimsProvider, PermissionService};
pub use service_impl::{AuthorizerImpl, AuthzClaimsProviderImpl, PermissionServiceImpl};
