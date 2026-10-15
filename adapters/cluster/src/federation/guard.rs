//! Services of a session store (federation mode, every service except the
//! authority).  Identity belongs to the authority: register, login, user,
//! role and permission writes are refused openly with
//! [`AuthError::NotAuthority`] (HTTP 421) naming the authority's instances.
//! What a session store can answer comes from the authority's snapshots.

use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use uuid::Uuid;

use crate::federation::membership::FederationClusterService;
use crate::federation::store::SyncStore;
use z_auth::identity::access::model::{NewRole, Role, RoleUpdate, UserRole};
use z_auth::identity::access::repository::{RoleRepository, UserRoleRepository};
use z_auth::identity::access::service::RoleService;
use z_auth::identity::user::model::{
    NewUser, RegisterUser, UpdateUser, User, UserPage, UserQuery, UserUpdate, UserWithRoles,
};
use z_auth::identity::user::repository::UserRepository;
use z_auth::identity::user::service::UserService;
use z_auth::security::authentication::account::{RefreshAccount, RefreshAccountSource};
use z_auth::security::authentication::model::{ClientContext, Credentials, TokenPair};
use z_auth::security::authentication::service::AuthenticationService;
use z_auth::security::authorization::catalog::CatalogCache;
use z_auth::security::authorization::model::{
    GrantView, NewPermission, Permission, PermissionCatalog, PermissionValue,
};
use z_auth::security::authorization::service::PermissionService;
use z_auth::security::token::model::Claims;
use z_auth::utils::error::AuthError;

/// Builds [`AuthError::NotAuthority`] with the authority's current
/// addresses.  Holds the cluster weakly (attached once it exists).
#[derive(Clone)]
pub struct Authority {
    service: String,
    cluster: Arc<OnceLock<Weak<FederationClusterService>>>,
}

impl Authority {
    pub(crate) fn new(service: String) -> Self {
        Self {
            service,
            cluster: Arc::default(),
        }
    }

    pub(crate) fn attach(&self, cluster: &Arc<FederationClusterService>) {
        let _ = self.cluster.set(Arc::downgrade(cluster));
    }

    pub fn error(&self) -> AuthError {
        AuthError::NotAuthority {
            service: self.service.clone(),
            addresses: self
                .cluster
                .get()
                .and_then(Weak::upgrade)
                .map(|c| c.addresses_of(&self.service))
                .unwrap_or_default(),
        }
    }

    fn deny<T>(&self) -> Result<T, AuthError> {
        Err(self.error())
    }
}

/// Every user operation belongs to the authority.
pub struct NotAuthorityUsers(pub Authority);

#[async_trait]
impl UserService for NotAuthorityUsers {
    async fn register(&self, _: RegisterUser) -> Result<User, AuthError> {
        self.0.deny()
    }
    async fn find_by_id(&self, _: Uuid) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn find_by_email(&self, _: &str) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn find_by_username(&self, _: &str) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn find_with_roles_by_id(&self, _: Uuid) -> Result<Option<UserWithRoles>, AuthError> {
        self.0.deny()
    }
    async fn find_with_roles_by_email(&self, _: &str) -> Result<Option<UserWithRoles>, AuthError> {
        self.0.deny()
    }
    async fn find_with_roles_by_username(
        &self,
        _: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.0.deny()
    }
    async fn list(&self, _: UserQuery) -> Result<UserPage, AuthError> {
        self.0.deny()
    }
    async fn update(&self, _: Uuid, _: UpdateUser) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn delete(&self, _: Uuid) -> Result<Option<Uuid>, AuthError> {
        self.0.deny()
    }
    async fn activate(&self, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn deactivate(&self, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
}

/// Every role operation belongs to the authority.
pub struct NotAuthorityRoles(pub Authority);

#[async_trait]
impl RoleService for NotAuthorityRoles {
    async fn create(&self, _: &NewRole) -> Result<Role, AuthError> {
        self.0.deny()
    }
    async fn find_by_id(&self, _: Uuid) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn find_by_name(&self, _: &str) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn find_by_code(&self, _: &str) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn exists_by_name(&self, _: &str) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn list(&self) -> Result<Vec<Role>, AuthError> {
        self.0.deny()
    }
    async fn update(&self, _: Uuid, _: &RoleUpdate) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn delete(&self, _: Uuid) -> Result<Option<Uuid>, AuthError> {
        self.0.deny()
    }
    async fn assign(&self, _: Uuid, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn revoke(&self, _: Uuid, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn has_role(&self, _: Uuid, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn list_user_assignments(&self, _: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.0.deny()
    }
    async fn list_user_assignment_history(&self, _: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.0.deny()
    }
    async fn revoke_all_for_user(&self, _: Uuid) -> Result<u64, AuthError> {
        self.0.deny()
    }
}

/// The catalog as published by the authority; writes are refused.
pub struct SnapshotPermissions {
    authority: Authority,
    store: Arc<dyn SyncStore>,
    cache: Arc<CatalogCache>,
}

impl SnapshotPermissions {
    pub(crate) fn new(
        authority: Authority,
        store: Arc<dyn SyncStore>,
        cache: Arc<CatalogCache>,
    ) -> Self {
        Self {
            authority,
            store,
            cache,
        }
    }
}

#[async_trait]
impl PermissionService for SnapshotPermissions {
    async fn define(&self, _: &NewPermission) -> Result<Permission, AuthError> {
        self.authority.deny()
    }
    async fn add_option(&self, _: &str, _: &str) -> Result<Permission, AuthError> {
        self.authority.deny()
    }
    async fn delete(&self, _: &str) -> Result<bool, AuthError> {
        self.authority.deny()
    }
    async fn grant_to_user(&self, _: Uuid, _: &str, _: &PermissionValue) -> Result<(), AuthError> {
        self.authority.deny()
    }
    async fn revoke_from_user(&self, _: Uuid, _: &str) -> Result<bool, AuthError> {
        self.authority.deny()
    }
    async fn grant_to_role(&self, _: Uuid, _: &str, _: &PermissionValue) -> Result<(), AuthError> {
        self.authority.deny()
    }
    async fn revoke_from_role(&self, _: Uuid, _: &str) -> Result<bool, AuthError> {
        self.authority.deny()
    }
    async fn user_grants(&self, _: Uuid) -> Result<Vec<GrantView>, AuthError> {
        self.authority.deny()
    }
    async fn role_grants(&self, _: Uuid) -> Result<Vec<GrantView>, AuthError> {
        self.authority.deny()
    }
    fn catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError> {
        Ok(self.cache.get())
    }
    async fn reload_catalog(&self) -> Result<Arc<PermissionCatalog>, AuthError> {
        match self.store.load_catalog().await? {
            Some(snapshot) if snapshot.catalog.version >= self.cache.version() => {
                Ok(self.cache.replace(snapshot.catalog))
            }
            _ => Ok(self.cache.get()),
        }
    }
}

/// Login belongs to the authority; everything else is served here.
pub struct NotAuthorityLogin {
    pub authority: Authority,
    pub inner: Arc<dyn AuthenticationService>,
}

#[async_trait]
impl AuthenticationService for NotAuthorityLogin {
    async fn login(&self, _: Credentials, _: ClientContext) -> Result<TokenPair, AuthError> {
        self.authority.deny()
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

/// A refresh on a session store reads the account snapshot the authority
/// published.  A missing snapshot means it has not arrived yet
/// ([`AuthError::ReplicaBehind`]; the refresh fetches it and retries).
pub struct SnapshotAccountSource {
    store: Arc<dyn SyncStore>,
}

impl SnapshotAccountSource {
    pub(crate) fn new(store: Arc<dyn SyncStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl RefreshAccountSource for SnapshotAccountSource {
    async fn load(&self, user_id: Uuid) -> Result<Option<RefreshAccount>, AuthError> {
        match self.store.load_account(user_id).await? {
            None => Err(AuthError::ReplicaBehind),
            Some(a) if a.deleted => Ok(None),
            Some(a) => Ok(Some(RefreshAccount {
                is_active: a.is_active,
                authz: a.authz.filter(|_| a.is_active),
            })),
        }
    }
}

/// A session store keeps no users.  Only login reads them, and login is
/// refused before it gets here.
pub(crate) struct NoUserStore(pub Authority);

#[async_trait]
impl UserRepository for NoUserStore {
    async fn find_by_id(&self, _: Uuid) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn find_by_email(&self, _: &str) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn find_by_username(&self, _: &str) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn find_with_roles_by_id(&self, _: Uuid) -> Result<Option<UserWithRoles>, AuthError> {
        self.0.deny()
    }
    async fn find_with_roles_by_email(&self, _: &str) -> Result<Option<UserWithRoles>, AuthError> {
        self.0.deny()
    }
    async fn find_with_roles_by_username(
        &self,
        _: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.0.deny()
    }
    async fn list(&self, _: &UserQuery) -> Result<UserPage, AuthError> {
        self.0.deny()
    }
    async fn exists_by_email(&self, _: &str) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn exists_by_username(&self, _: &str) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn create(&self, _: NewUser) -> Result<User, AuthError> {
        self.0.deny()
    }
    async fn update(&self, _: Uuid, _: UserUpdate) -> Result<Option<User>, AuthError> {
        self.0.deny()
    }
    async fn delete(&self, _: Uuid) -> Result<Option<Uuid>, AuthError> {
        self.0.deny()
    }
    async fn activate(&self, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn deactivate(&self, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn is_active(&self, _: Uuid) -> Result<Option<bool>, AuthError> {
        self.0.deny()
    }
    async fn is_verified(&self, _: Uuid) -> Result<Option<bool>, AuthError> {
        self.0.deny()
    }
}

/// A session store keeps no roles.
pub(crate) struct NoRoleStore(pub Authority);

#[async_trait]
impl RoleRepository for NoRoleStore {
    async fn create(&self, _: &NewRole) -> Result<Role, AuthError> {
        self.0.deny()
    }
    async fn find_by_id(&self, _: Uuid) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn find_by_name(&self, _: &str) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn find_by_code(&self, _: &str) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn list_all(&self) -> Result<Vec<Role>, AuthError> {
        self.0.deny()
    }
    async fn update(&self, _: Uuid, _: &RoleUpdate) -> Result<Option<Role>, AuthError> {
        self.0.deny()
    }
    async fn delete(&self, _: Uuid) -> Result<Option<Uuid>, AuthError> {
        self.0.deny()
    }
    async fn exists_by_name(&self, _: &str) -> Result<bool, AuthError> {
        self.0.deny()
    }
}

/// A session store keeps no role assignments.
pub(crate) struct NoUserRoleStore(pub Authority);

#[async_trait]
impl UserRoleRepository for NoUserRoleStore {
    async fn assign(&self, _: Uuid, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn revoke(&self, _: Uuid, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn is_role_active(&self, _: Uuid, _: Uuid) -> Result<bool, AuthError> {
        self.0.deny()
    }
    async fn list_active_for_user(&self, _: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.0.deny()
    }
    async fn list_all_for_user(&self, _: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.0.deny()
    }
    async fn revoke_all_for_user(&self, _: Uuid) -> Result<u64, AuthError> {
        self.0.deny()
    }
}
