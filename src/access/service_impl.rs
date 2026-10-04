//! Access-control service implementation.
//!
//! [`RoleServiceImpl`] implements [`RoleService`] on top of the
//! [`RoleRepository`] and [`UserRoleRepository`] ports.  Every operation is
//! refused with [`AuthError::AuthzModeDisabled`] unless the configured
//! authorization mode uses roles.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    access::{
        model::{NewRole, Role, UserRole},
        repository::{RoleRepository, UserRoleRepository},
        service::RoleService,
    },
    authorization::validation::validate_code,
    config::AuthzMode,
    error::AuthError,
};

const ROLES: &str = "role management";

/// Default implementation of [`RoleService`].
pub struct RoleServiceImpl {
    role_repo: Arc<dyn RoleRepository>,
    user_role_repo: Arc<dyn UserRoleRepository>,
    mode: AuthzMode,
}

impl RoleServiceImpl {
    pub fn new(
        role_repo: Arc<dyn RoleRepository>,
        user_role_repo: Arc<dyn UserRoleRepository>,
        mode: AuthzMode,
    ) -> Self {
        Self {
            role_repo,
            user_role_repo,
            mode,
        }
    }

    fn enabled(&self) -> Result<(), AuthError> {
        if self.mode.uses_roles() {
            Ok(())
        } else {
            Err(AuthError::AuthzModeDisabled(ROLES))
        }
    }
}

#[async_trait]
impl RoleService for RoleServiceImpl {
    async fn create(&self, new_role: &NewRole) -> Result<Role, AuthError> {
        self.enabled()?;
        validate_code(&new_role.code)?;
        self.role_repo.create(new_role).await
    }
    async fn find_by_id(&self, role_id: Uuid) -> Result<Option<Role>, AuthError> {
        self.enabled()?;
        self.role_repo.find_by_id(role_id).await
    }
    async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        self.enabled()?;
        self.role_repo.find_by_name(name).await
    }
    async fn find_by_code(&self, code: &str) -> Result<Option<Role>, AuthError> {
        self.enabled()?;
        self.role_repo.find_by_code(code).await
    }
    async fn exists_by_name(&self, name: &str) -> Result<bool, AuthError> {
        self.enabled()?;
        self.role_repo.exists_by_name(name).await
    }
    async fn list(&self) -> Result<Vec<Role>, AuthError> {
        self.enabled()?;
        self.role_repo.list_all().await
    }
    async fn delete(&self, role_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        self.enabled()?;
        self.role_repo.delete(role_id).await
    }

    async fn assign(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        self.enabled()?;
        self.user_role_repo.assign(user_id, role_id).await
    }
    async fn revoke(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        self.enabled()?;
        self.user_role_repo.revoke(user_id, role_id).await
    }
    async fn has_role(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthError> {
        self.enabled()?;
        self.user_role_repo.is_role_active(user_id, role_id).await
    }
    async fn list_user_assignments(&self, user_id: Uuid) -> Result<Vec<UserRole>, AuthError> {
        self.enabled()?;
        self.user_role_repo.list_active_for_user(user_id).await
    }
    async fn list_user_assignment_history(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserRole>, AuthError> {
        self.enabled()?;
        self.user_role_repo.list_all_for_user(user_id).await
    }
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, AuthError> {
        self.enabled()?;
        self.user_role_repo.revoke_all_for_user(user_id).await
    }
}
