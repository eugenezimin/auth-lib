/// Auth service implementation.
///
/// [`AuthServiceImpl`] is the concrete type that implements [`AuthService`].
/// It orchestrates the registration flow by coordinating:
///
/// 1. Input validation  (email format, password strength)
/// 2. Uniqueness checks (via [`UserRepo`])
/// 3. Password hashing  (via [`crate::auth::password`])
/// 4. JWT-secret generation
/// 5. Persistence       (via [`UserRepo::create`])
///
/// All storage access goes through the [`UserRepo`] trait so the service
/// stays testable without a real database.
use std::sync::Arc;

use uuid::Uuid;

use crate::auth::password::{self, validate_password};
use crate::interfaces::auth::AuthService;
use crate::interfaces::db::role_repo::RoleRepo;
use crate::interfaces::db::user_repo::UserRepo;
use crate::interfaces::db::user_role_repo::UserRoleRepo;
use crate::model::config::DatabaseConfig;
use crate::model::role::{NewRole, Role};
use crate::model::user::{NewUser, RegisterRequest, User, UserWithRoles};
use crate::storage::db_factory::{build_role_repo, build_user_repo, build_user_role_repo};
use crate::storage::postgres::pg_pool::build_pool;
use crate::utils::errors::AuthError;

/// Concrete implementation of [`AuthService`].
///
/// Construct once at startup and share behind `Arc<dyn AuthService>`:
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use auth_lib::auth::register::AuthServiceImpl;
/// use auth_lib::storage::pg_pool::PgUserRepo;
///
/// let repo = Arc::new(PgUserRepo::new(pool.clone()));
/// let auth = Arc::new(AuthServiceImpl::new(repo));
/// ```
pub struct AuthServiceImpl {
    user_repo: Arc<dyn UserRepo>,
    role_repo: Arc<dyn RoleRepo>,
    user_role_repo: Arc<dyn UserRoleRepo>,
}

impl AuthServiceImpl {
    pub async fn build(db_config: &DatabaseConfig) -> Result<Arc<dyn AuthService>, AuthError> {
        let pool = build_pool(db_config)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let user_repo = build_user_repo(db_config)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let role_repo = build_role_repo(db_config)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let user_role_repo = build_user_role_repo(db_config)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(Arc::new(Self {
            user_repo,
            role_repo,
            user_role_repo,
        }))
    }
}

#[async_trait::async_trait]
impl AuthService for AuthServiceImpl {
    /// Register a new user account.
    ///
    /// # Flow
    ///
    /// ```text
    /// RegisterRequest
    ///       │
    ///       ├─ 1. validate_email()          → AuthError::InvalidEmail
    ///       ├─ 2. validate_password()       → AuthError::WeakPassword
    ///       ├─ 3. repo.exists_by_email()    → AuthError::EmailAlreadyTaken
    ///       ├─ 4. repo.exists_by_username() → AuthError::UsernameAlreadyTaken
    ///       ├─ 5. password::hash()          → AuthError::HashingError
    ///       ├─ 6. generate jwt_secret
    ///       ├─ 7. repo.create(NewUser)      → AuthError::DatabaseError
    ///       │
    ///       └─ User wit empty roles
    /// ```
    async fn register(&self, req: RegisterRequest) -> Result<User, AuthError> {
        validate_email(&req.email)?;
        validate_password(&req.password)?;

        if self.user_repo.exists_by_email(&req.email).await? {
            return Err(AuthError::EmailAlreadyTaken);
        }

        if let Some(ref username) = req.username {
            if self.user_repo.exists_by_username(username).await? {
                return Err(AuthError::UsernameAlreadyTaken);
            }
        }

        let password_hash = password::hash_password(&req.password)?;

        // A random UUID gives 122 bits of entropy — sufficient as an HMAC key.
        // Replacing this value later invalidates all existing tokens for the user.
        let jwt_secret = Uuid::new_v4().to_string();

        let new_user = NewUser {
            email: req.email,
            password_hash,
            jwt_secret,
            username: req.username,
            first_name: req.first_name,
            last_name: req.last_name,
        };

        let user = self.user_repo.create(new_user).await?;

        Ok(user)
    }
    async fn find_user_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>, AuthError> {
        self.user_repo.find_by_id(user_id).await
    }
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        self.user_repo.find_by_email(email).await
    }
    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        self.user_repo.find_by_username(username).await
    }
    async fn find_user_with_roles_by_id(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.user_repo.find_with_roles_by_id(user_id).await
    }
    async fn find_user_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.user_repo.find_with_roles_by_email(email).await
    }
    async fn find_user_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.user_repo.find_with_roles_by_username(username).await
    }

    async fn update_user(
        &self,
        user_id: uuid::Uuid,
        update: RegisterRequest,
    ) -> Result<Option<User>, AuthError> {
        self.user_repo.update(user_id, update).await
    }
    async fn delete_user(&self, user_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError> {
        self.user_repo.delete(user_id).await?;
        Ok(Some(user_id))
    }
    async fn activate_user(&self, user_id: uuid::Uuid) -> Result<bool, AuthError> {
        self.user_repo.activate(user_id).await
    }
    async fn deactivate_user(&self, user_id: uuid::Uuid) -> Result<bool, AuthError> {
        self.user_repo.deactivate(user_id).await
    }
    async fn create_role(&self, new_role: &NewRole) -> Result<Role, AuthError> {
        self.role_repo.create(new_role).await
    }
    async fn find_role_by_id(&self, role_id: uuid::Uuid) -> Result<Option<Role>, AuthError> {
        self.role_repo.find_by_id(role_id).await
    }
    async fn find_role_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        self.role_repo.find_by_name(name).await
    }
    async fn exists_role_by_name(&self, name: &str) -> Result<bool, AuthError> {
        self.role_repo.exists_by_name(name).await
    }
    async fn list_roles(&self) -> Result<Vec<Role>, AuthError> {
        self.role_repo.list_all().await
    }
    async fn delete_role(&self, role_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, AuthError> {
        self.role_repo.delete(role_id).await
    }
    async fn assign_role(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError> {
        self.user_role_repo.assign(user_id, role_id).await
    }
    async fn revoke_role(
        &self,
        user_id: uuid::Uuid,
        role_id: uuid::Uuid,
    ) -> Result<bool, AuthError> {
        self.user_role_repo.revoke(user_id, role_id).await
    }
}

/// Basic email format validation.
fn validate_email(email: &str) -> Result<(), AuthError> {
    let parts: Vec<&str> = email.splitn(2, '@').collect();

    let valid = parts.len() == 2
        && !parts[0].is_empty()
        && parts[1].contains('.')
        && !parts[1].starts_with('.')
        && !parts[1].ends_with('.');

    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidEmail(format!(
            "'{email}' is not a valid email address"
        )))
    }
}
