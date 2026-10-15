//! Default implementations of the authorization services.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::conf::config::AuthzMode;
use crate::identity::user::model::UserWithRoles;
use crate::security::authorization::catalog::CatalogCache;
use crate::security::authorization::codec::PermissionCodec;
use crate::security::authorization::events::CatalogEvents;
use crate::security::authorization::model::{
    EffectivePermissions, GrantView, NewPermission, Permission, PermissionAssignment,
    PermissionCatalog, PermissionKind, PermissionValue,
};
use crate::security::authorization::repository::PermissionRepository;
use crate::security::authorization::service::{Authorizer, AuthzClaimsProvider, PermissionService};
use crate::security::authorization::validation::{assignment_for, value_of};
use crate::security::token::model::{AuthzClaims, Claims};
use crate::utils::error::AuthError;
use crate::utils::validation::validate_code;

const PERMISSIONS: &str = "permission management";
const ROLE_GRANTS: &str = "granting permissions to roles";

/// The repository, if the mode enables permissions.  The facade guarantees
/// a repository is supplied in those modes.
fn enabled(
    mode: AuthzMode,
    repo: &Option<Arc<dyn PermissionRepository>>,
) -> Result<&dyn PermissionRepository, AuthError> {
    match repo {
        Some(repo) if mode.uses_permissions() => Ok(repo.as_ref()),
        _ => Err(AuthError::AuthzModeDisabled(PERMISSIONS)),
    }
}

// ── PermissionService ─────────────────────────────────────────────────────────

/// Default [`PermissionService`].
pub struct PermissionServiceImpl {
    mode: AuthzMode,
    repo: Option<Arc<dyn PermissionRepository>>,
    cache: Arc<CatalogCache>,
    events: Arc<dyn CatalogEvents>,
}

impl PermissionServiceImpl {
    pub fn new(
        mode: AuthzMode,
        repo: Option<Arc<dyn PermissionRepository>>,
        cache: Arc<CatalogCache>,
        events: Arc<dyn CatalogEvents>,
    ) -> Self {
        Self {
            mode,
            repo,
            cache,
            events,
        }
    }

    /// Reload this instance's cache and tell the others the catalog changed.
    async fn catalog_changed(&self) -> Result<(), AuthError> {
        let catalog = self.reload_catalog().await?;
        self.events.catalog_changed(catalog.version).await;
        Ok(())
    }

    fn repo(&self) -> Result<&dyn PermissionRepository, AuthError> {
        enabled(self.mode, &self.repo)
    }

    async fn require(&self, code: &str) -> Result<Permission, AuthError> {
        self.repo()?
            .find_by_code(code)
            .await?
            .ok_or(AuthError::PermissionNotFound)
    }

    /// Decode stored assignments with the cached catalog.  A permission the
    /// cache doesn't know yet (defined on another instance) triggers one
    /// reload; one still missing after it was deleted meanwhile and is
    /// skipped.
    async fn views(
        &self,
        assignments: Vec<PermissionAssignment>,
    ) -> Result<Vec<GrantView>, AuthError> {
        let mut catalog = self.cache.get();
        let known = |c: &PermissionCatalog, a: &PermissionAssignment| {
            c.permissions.iter().any(|p| p.id == a.permission_id)
        };
        if assignments.iter().any(|a| !known(&catalog, a)) {
            catalog = self.reload_catalog().await?;
        }
        let mut views: Vec<GrantView> = assignments
            .iter()
            .filter_map(|a| {
                let permission = catalog.permissions.iter().find(|p| p.id == a.permission_id)?;
                Some(GrantView {
                    permission_code: permission.code.clone(),
                    value: value_of(permission, a)?,
                })
            })
            .collect();
        views.sort_by(|a, b| a.permission_code.cmp(&b.permission_code));
        Ok(views)
    }
}

#[async_trait]
impl PermissionService for PermissionServiceImpl {
    async fn define(&self, permission: &NewPermission) -> Result<Permission, AuthError> {
        let repo = self.repo()?;
        validate_code(&permission.code)?;
        let choosable = matches!(
            permission.kind,
            PermissionKind::Single | PermissionKind::Multi
        );
        if choosable == permission.options.is_empty() {
            return Err(AuthError::InvalidPermissionValue(format!(
                "{}: single / multi permissions need options; others take none",
                permission.code
            )));
        }
        for option in &permission.options {
            validate_code(option)?;
        }
        let created = repo.create(permission).await?;
        self.catalog_changed().await?;
        Ok(created)
    }

    async fn add_option(
        &self,
        permission_code: &str,
        option_code: &str,
    ) -> Result<Permission, AuthError> {
        validate_code(option_code)?;
        let permission = self.require(permission_code).await?;
        if !matches!(
            permission.kind,
            PermissionKind::Single | PermissionKind::Multi
        ) {
            return Err(AuthError::InvalidPermissionValue(format!(
                "{permission_code}: only single / multi permissions have options"
            )));
        }
        if permission.options.iter().any(|o| o.code == option_code) {
            return Err(AuthError::InvalidCode(format!(
                "option '{option_code}' already exists"
            )));
        }
        let updated = self.repo()?.add_option(permission.id, option_code).await?;
        self.catalog_changed().await?;
        Ok(updated)
    }

    async fn delete(&self, permission_code: &str) -> Result<bool, AuthError> {
        let repo = self.repo()?;
        let Some(permission) = repo.find_by_code(permission_code).await? else {
            return Ok(false);
        };
        let deleted = repo.delete(permission.id).await?;
        self.catalog_changed().await?;
        Ok(deleted)
    }

    async fn grant_to_user(
        &self,
        user_id: Uuid,
        permission_code: &str,
        value: &PermissionValue,
    ) -> Result<(), AuthError> {
        let assignment = assignment_for(&self.require(permission_code).await?, value)?;
        self.repo()?.replace_user_grant(user_id, &assignment).await
    }

    async fn revoke_from_user(
        &self,
        user_id: Uuid,
        permission_code: &str,
    ) -> Result<bool, AuthError> {
        let permission = self.require(permission_code).await?;
        self.repo()?.clear_user_grant(user_id, permission.id).await
    }

    async fn grant_to_role(
        &self,
        role_id: Uuid,
        permission_code: &str,
        value: &PermissionValue,
    ) -> Result<(), AuthError> {
        if !self.mode.role_grants() {
            return Err(AuthError::AuthzModeDisabled(ROLE_GRANTS));
        }
        let assignment = assignment_for(&self.require(permission_code).await?, value)?;
        self.repo()?.replace_role_grant(role_id, &assignment).await
    }

    async fn revoke_from_role(
        &self,
        role_id: Uuid,
        permission_code: &str,
    ) -> Result<bool, AuthError> {
        if !self.mode.role_grants() {
            return Err(AuthError::AuthzModeDisabled(ROLE_GRANTS));
        }
        let permission = self.require(permission_code).await?;
        self.repo()?.clear_role_grant(role_id, permission.id).await
    }

    async fn user_grants(&self, user_id: Uuid) -> Result<Vec<GrantView>, AuthError> {
        let assignments = self.repo()?.list_user_grants(user_id).await?;
        self.views(assignments).await
    }

    async fn role_grants(&self, role_id: Uuid) -> Result<Vec<GrantView>, AuthError> {
        if !self.mode.role_grants() {
            return Err(AuthError::AuthzModeDisabled(ROLE_GRANTS));
        }
        let assignments = self.repo()?.list_role_grants(role_id).await?;
        self.views(assignments).await
    }

    fn catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError> {
        self.repo()?;
        Ok(self.cache.get())
    }

    async fn reload_catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError> {
        let catalog = self.repo()?.load_catalog().await?;
        Ok(self.cache.replace(catalog))
    }
}

// ── Authorizer ────────────────────────────────────────────────────────────────

/// Default [`Authorizer`]: decodes with the shared [`CatalogCache`].
pub struct AuthorizerImpl {
    cache: Arc<CatalogCache>,
    codec: Arc<dyn PermissionCodec>,
}

impl AuthorizerImpl {
    pub fn new(cache: Arc<CatalogCache>, codec: Arc<dyn PermissionCodec>) -> Self {
        Self { cache, codec }
    }
}

impl Authorizer for AuthorizerImpl {
    fn roles<'a>(&self, claims: &'a Claims) -> &'a [String] {
        claims.authz.as_ref().map_or(&[], |a| a.roles.as_slice())
    }

    fn has_role(&self, claims: &Claims, role_code: &str) -> bool {
        self.roles(claims).iter().any(|r| r == role_code)
    }

    fn permissions(&self, claims: &Claims) -> EffectivePermissions {
        match claims.authz.as_ref().and_then(|a| a.permissions.as_ref()) {
            Some(encoded) => self.codec.decode(encoded, &self.cache.get()),
            None => EffectivePermissions::default(),
        }
    }
}

// ── AuthzClaimsProvider ───────────────────────────────────────────────────────

/// Default [`AuthzClaimsProvider`].  Roles come with the account (already
/// loaded by login / refresh); permissions cost one repository call.
pub struct AuthzClaimsProviderImpl {
    mode: AuthzMode,
    repo: Option<Arc<dyn PermissionRepository>>,
    codec: Arc<dyn PermissionCodec>,
    cache: Arc<CatalogCache>,
}

impl AuthzClaimsProviderImpl {
    pub fn new(
        mode: AuthzMode,
        repo: Option<Arc<dyn PermissionRepository>>,
        codec: Arc<dyn PermissionCodec>,
        cache: Arc<CatalogCache>,
    ) -> Self {
        Self {
            mode,
            repo,
            codec,
            cache,
        }
    }
}

#[async_trait]
impl AuthzClaimsProvider for AuthzClaimsProviderImpl {
    async fn claims_for(&self, account: &UserWithRoles) -> Result<Option<AuthzClaims>, AuthError> {
        if self.mode == AuthzMode::None {
            return Ok(None);
        }

        let mut roles: Vec<String> = if self.mode.uses_roles() {
            account.roles.iter().map(|r| r.code.clone()).collect()
        } else {
            Vec::new()
        };
        roles.sort();

        let permissions = if self.mode.uses_permissions() {
            let repo = enabled(self.mode, &self.repo)?;
            let grants = repo
                .effective_grants(account.user.id, self.mode.role_grants())
                .await?;
            // The catalog grew since this instance loaded it: refresh the
            // cache now, while we are on the store-reading path anyway.
            if grants.catalog_version > self.cache.version() {
                self.cache.replace(repo.load_catalog().await?);
            }
            Some(self.codec.encode(&grants))
        } else {
            None
        };

        Ok(Some(AuthzClaims { roles, permissions }))
    }
}
