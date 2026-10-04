//! Authorization service interfaces.
//!
//! - [`PermissionService`] — catalog and grant administration, catalog for UIs.
//! - [`Authorizer`] — request-time checks from a verified token; **no I/O**.
//! - [`AuthzClaimsProvider`] — builds the token's authorization claims at
//!   login / refresh (the only regular path that reads the store).

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::authorization::model::{
    EffectivePermissions, NewPermission, Permission, PermissionCatalog, PermissionValue,
};
use crate::error::AuthError;
use crate::token::model::{AuthzClaims, Claims};
use crate::user::model::UserWithRoles;

/// Catalog and grant administration.  Requires a mode with permissions
/// (`permissions` / `combined`); role grants require `combined`.  Grant
/// changes take effect at the user's next refresh.
#[async_trait]
pub trait PermissionService: Send + Sync {
    /// Add a catalog entry.
    async fn define(&self, permission: &NewPermission) -> Result<Permission, AuthError>;
    /// Add an option to a `single` / `multi` permission.
    async fn add_option(
        &self,
        permission_code: &str,
        option_code: &str,
    ) -> Result<Permission, AuthError>;
    /// Delete a catalog entry and all its grants.  `false` if missing.
    async fn delete(&self, permission_code: &str) -> Result<bool, AuthError>;

    /// Grant (or replace) a value for a user.
    async fn grant_to_user(
        &self,
        user_id: Uuid,
        permission_code: &str,
        value: &PermissionValue,
    ) -> Result<(), AuthError>;
    async fn revoke_from_user(
        &self,
        user_id: Uuid,
        permission_code: &str,
    ) -> Result<bool, AuthError>;
    /// Grant (or replace) a value for a role (`combined` mode).
    async fn grant_to_role(
        &self,
        role_id: Uuid,
        permission_code: &str,
        value: &PermissionValue,
    ) -> Result<(), AuthError>;
    async fn revoke_from_role(
        &self,
        role_id: Uuid,
        permission_code: &str,
    ) -> Result<bool, AuthError>;

    /// The cached catalog — what UIs fetch to decode tokens.  No I/O.
    fn catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError>;
    /// Load the catalog from the store into the cache (call at startup).
    async fn reload_catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError>;
}

/// Authorization checks against a verified token.  Pure memory: decodes the
/// token's claims with the cached catalog.  Mode-agnostic, so services that
/// only verify tokens can use it as well.
pub trait Authorizer: Send + Sync {
    /// Role codes in the token (empty if none).
    fn roles<'a>(&self, claims: &'a Claims) -> &'a [String];
    fn has_role(&self, claims: &Claims, role_code: &str) -> bool;
    /// The token's permissions, decoded.
    fn permissions(&self, claims: &Claims) -> EffectivePermissions;
}

/// Builds the authorization claims of a token being minted.
#[async_trait]
pub trait AuthzClaimsProvider: Send + Sync {
    /// `None` when the mode is `none`.
    async fn claims_for(&self, account: &UserWithRoles) -> Result<Option<AuthzClaims>, AuthError>;
}
