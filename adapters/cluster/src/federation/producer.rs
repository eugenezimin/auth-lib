//! The authority's side (federation mode): after every identity write, the
//! account snapshot of each affected user — and, for catalog changes, the
//! catalog snapshot — is recomputed and stored.  The feed carries them to
//! every session store, where refreshes read them.
//!
//! | write | republished |
//! |-------|-------------|
//! | register, update, activate, deactivate, delete | that user |
//! | login | that user (so the snapshot exists before the first refresh elsewhere) |
//! | role assign / revoke / revoke all | that user |
//! | role delete, role grant changes | every holder of the role |
//! | user grant changes | that user |
//! | permission define / add option / delete | the catalog |

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::federation::store::SyncStore;
use crate::sync::{AccountSnapshot, CatalogSnapshot};
use z_auth::identity::access::model::{NewRole, Role, RoleUpdate, UserRole};
use z_auth::identity::access::repository::UserRoleRepository;
use z_auth::identity::access::service::RoleService;
use z_auth::identity::user::model::{
    RegisterUser, UpdateUser, User, UserPage, UserQuery, UserWithRoles,
};
use z_auth::identity::user::service::UserService;
use z_auth::security::authentication::account::RefreshAccountSource;
use z_auth::security::authentication::model::{ClientContext, Credentials, TokenPair};
use z_auth::security::authentication::service::AuthenticationService;
use z_auth::security::authorization::model::{
    GrantView, NewPermission, Permission, PermissionCatalog, PermissionValue,
};
use z_auth::security::authorization::service::PermissionService;
use z_auth::security::token::codec::AccessTokenDecoder;
use z_auth::security::token::model::{Claims, ExpiryCheck};
use z_auth::utils::clock::Clock;
use z_auth::utils::error::AuthError;

pub struct SnapshotProducer {
    accounts: Arc<dyn RefreshAccountSource>,
    store: Arc<dyn SyncStore>,
    user_roles: Arc<dyn UserRoleRepository>,
    permissions: Arc<dyn PermissionService>,
    uses_permissions: bool,
}

impl SnapshotProducer {
    pub(crate) fn new(
        accounts: Arc<dyn RefreshAccountSource>,
        store: Arc<dyn SyncStore>,
        user_roles: Arc<dyn UserRoleRepository>,
        permissions: Arc<dyn PermissionService>,
        uses_permissions: bool,
    ) -> Self {
        Self {
            accounts,
            store,
            user_roles,
            permissions,
            uses_permissions,
        }
    }

    /// Recompute and store a user's snapshot (if it changed).
    pub async fn account_changed(&self, user_id: Uuid) -> Result<(), AuthError> {
        let (is_active, deleted, authz) = match self.accounts.load(user_id).await? {
            None => (false, true, None),
            Some(a) => (a.is_active, false, a.authz),
        };
        if let Some(existing) = self.store.load_account(user_id).await?
            && existing.is_active == is_active
            && existing.deleted == deleted
            && existing.authz == authz
        {
            return Ok(());
        }
        let version = self.store.next_version().await?;
        self.store
            .apply_account(&AccountSnapshot {
                user_id,
                version,
                is_active,
                deleted,
                authz,
            })
            .await?;
        Ok(())
    }

    async fn accounts_changed(&self, users: Vec<Uuid>) -> Result<(), AuthError> {
        for user in users {
            self.account_changed(user).await?;
        }
        Ok(())
    }

    async fn holders(&self, role_id: Uuid) -> Result<Vec<Uuid>, AuthError> {
        self.user_roles.list_active_holders(role_id).await
    }

    /// Store the current catalog as a snapshot.
    pub async fn catalog_changed(&self) -> Result<(), AuthError> {
        if !self.uses_permissions {
            return Ok(());
        }
        let catalog = self.permissions.catalog()?;
        self.store
            .apply_catalog(&CatalogSnapshot {
                version: catalog.version,
                catalog: (*catalog).clone(),
            })
            .await?;
        Ok(())
    }
}

/// [`UserService`] that republishes the user's snapshot after writes.
pub struct ProducingUsers {
    pub inner: Arc<dyn UserService>,
    pub producer: Arc<SnapshotProducer>,
}

#[async_trait]
impl UserService for ProducingUsers {
    async fn register(&self, req: RegisterUser) -> Result<User, AuthError> {
        let user = self.inner.register(req).await?;
        self.producer.account_changed(user.id).await?;
        Ok(user)
    }
    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        self.inner.find_by_id(user_id).await
    }
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        self.inner.find_by_email(email).await
    }
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        self.inner.find_by_username(username).await
    }
    async fn find_with_roles_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.inner.find_with_roles_by_id(user_id).await
    }
    async fn find_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.inner.find_with_roles_by_email(email).await
    }
    async fn find_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.inner.find_with_roles_by_username(username).await
    }
    async fn list(&self, query: UserQuery) -> Result<UserPage, AuthError> {
        self.inner.list(query).await
    }
    async fn update(&self, user_id: Uuid, update: UpdateUser) -> Result<Option<User>, AuthError> {
        let updated = self.inner.update(user_id, update).await?;
        if updated.is_some() {
            self.producer.account_changed(user_id).await?;
        }
        Ok(updated)
    }
    async fn delete(&self, user_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let deleted = self.inner.delete(user_id).await?;
        if deleted.is_some() {
            self.producer.account_changed(user_id).await?;
        }
        Ok(deleted)
    }
    async fn activate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        let changed = self.inner.activate(user_id).await?;
        self.producer.account_changed(user_id).await?;
        Ok(changed)
    }
    async fn deactivate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        let changed = self.inner.deactivate(user_id).await?;
        self.producer.account_changed(user_id).await?;
        Ok(changed)
    }
}

/// [`RoleService`] that republishes affected users' snapshots.
pub struct ProducingRoles {
    pub inner: Arc<dyn RoleService>,
    pub producer: Arc<SnapshotProducer>,
}

#[async_trait]
impl RoleService for ProducingRoles {
    async fn create(&self, role: &NewRole) -> Result<Role, AuthError> {
        self.inner.create(role).await
    }
    async fn find_by_id(&self, role_id: Uuid) -> Result<Option<Role>, AuthError> {
        self.inner.find_by_id(role_id).await
    }
    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        self.inner.find_by_name(name).await
    }
    async fn find_by_code(&self, code: &str) -> Result<Option<Role>, AuthError> {
        self.inner.find_by_code(code).await
    }
    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError> {
        self.inner.exists_by_name(name).await
    }
    async fn list(&self) -> Result<Vec<Role>, AuthError> {
        self.inner.list().await
    }
    async fn update(&self, role_id: Uuid, update: &RoleUpdate) -> Result<Option<Role>, AuthError> {
        // Snapshots carry role codes only, and the code never changes.
        self.inner.update(role_id, update).await
    }
    async fn delete(&self, role_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        // Holders are gone from the store once the role is.
        let holders = self.producer.holders(role_id).await?;
        let deleted = self.inner.delete(role_id).await?;
        if deleted.is_some() {
            self.producer.accounts_changed(holders).await?;
        }
        Ok(deleted)
    }
    async fn assign(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        let changed = self.inner.assign(user_id, role_id).await?;
        self.producer.account_changed(user_id).await?;
        Ok(changed)
    }
    async fn revoke(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        let changed = self.inner.revoke(user_id, role_id).await?;
        self.producer.account_changed(user_id).await?;
        Ok(changed)
    }
    async fn has_role(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        self.inner.has_role(user_id, role_id).await
    }
    async fn list_user_assignments(&self, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.inner.list_user_assignments(user_id).await
    }
    async fn list_user_assignment_history(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserRole>, AuthError> {
        self.inner.list_user_assignment_history(user_id).await
    }
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let n = self.inner.revoke_all_for_user(user_id).await?;
        self.producer.account_changed(user_id).await?;
        Ok(n)
    }
}

/// [`PermissionService`] that republishes the catalog and affected users.
pub struct ProducingPermissions {
    pub inner: Arc<dyn PermissionService>,
    pub producer: Arc<SnapshotProducer>,
}

#[async_trait]
impl PermissionService for ProducingPermissions {
    async fn define(&self, permission: &NewPermission) -> Result<Permission, AuthError> {
        let p = self.inner.define(permission).await?;
        self.producer.catalog_changed().await?;
        Ok(p)
    }
    async fn add_option(
        &self,
        permission_code: &str,
        option_code: &str,
    ) -> Result<Permission, AuthError> {
        let p = self.inner.add_option(permission_code, option_code).await?;
        self.producer.catalog_changed().await?;
        Ok(p)
    }
    async fn delete(&self, permission_code: &str) -> Result<bool, AuthError> {
        // Tokens decode against the catalog, so a removed permission drops
        // out of every token without republishing accounts.
        let deleted = self.inner.delete(permission_code).await?;
        self.producer.catalog_changed().await?;
        Ok(deleted)
    }
    async fn grant_to_user(
        &self,
        user_id: Uuid,
        permission_code: &str,
        value: &PermissionValue,
    ) -> Result<(), AuthError> {
        self.inner
            .grant_to_user(user_id, permission_code, value)
            .await?;
        self.producer.account_changed(user_id).await
    }
    async fn revoke_from_user(
        &self,
        user_id: Uuid,
        permission_code: &str,
    ) -> Result<bool, AuthError> {
        let changed = self
            .inner
            .revoke_from_user(user_id, permission_code)
            .await?;
        self.producer.account_changed(user_id).await?;
        Ok(changed)
    }
    async fn grant_to_role(
        &self,
        role_id: Uuid,
        permission_code: &str,
        value: &PermissionValue,
    ) -> Result<(), AuthError> {
        self.inner
            .grant_to_role(role_id, permission_code, value)
            .await?;
        let holders = self.producer.holders(role_id).await?;
        self.producer.accounts_changed(holders).await
    }
    async fn revoke_from_role(
        &self,
        role_id: Uuid,
        permission_code: &str,
    ) -> Result<bool, AuthError> {
        let changed = self
            .inner
            .revoke_from_role(role_id, permission_code)
            .await?;
        let holders = self.producer.holders(role_id).await?;
        self.producer.accounts_changed(holders).await?;
        Ok(changed)
    }
    async fn user_grants(&self, user_id: Uuid) -> Result<Vec<GrantView>, AuthError> {
        self.inner.user_grants(user_id).await
    }
    async fn role_grants(&self, role_id: Uuid) -> Result<Vec<GrantView>, AuthError> {
        self.inner.role_grants(role_id).await
    }
    fn catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError> {
        self.inner.catalog()
    }
    async fn reload_catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError> {
        self.inner.reload_catalog().await
    }
}

/// [`AuthenticationService`] that makes sure the user's snapshot exists
/// before the session reaches other clusters.
pub struct ProducingLogin {
    pub inner: Arc<dyn AuthenticationService>,
    pub producer: Arc<SnapshotProducer>,
    pub decoder: Arc<dyn AccessTokenDecoder>,
    pub clock: Arc<dyn Clock>,
}

#[async_trait]
impl AuthenticationService for ProducingLogin {
    async fn login(
        &self,
        credentials: Credentials,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        let pair = self.inner.login(credentials, ctx).await?;
        let claims =
            self.decoder
                .decode(&pair.access_token, self.clock.now(), ExpiryCheck::Ignore)?;
        self.producer.account_changed(claims.sub).await?;
        Ok(pair)
    }
    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
        ctx: ClientContext,
    ) -> Result<TokenPair, AuthError> {
        self.inner.refresh(access_token, refresh_token, ctx).await
    }
    async fn logout(&self, access_token: &str) -> Result<bool, AuthError> {
        self.inner.logout(access_token).await
    }
    async fn logout_all(&self, user_id: Uuid) -> Result<u64, AuthError> {
        self.inner.logout_all(user_id).await
    }
    async fn verify_access_token(&self, access_token: &str) -> Result<Claims, AuthError> {
        self.inner.verify_access_token(access_token).await
    }
    async fn purge_sessions(&self, retention: std::time::Duration) -> Result<u64, AuthError> {
        self.inner.purge_sessions(retention).await
    }
}
