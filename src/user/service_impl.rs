//! User service implementation.
//!
//! [`UserServiceImpl`] implements [`UserService`] by coordinating:
//!
//! 1. Input validation  (email format, password policy)
//! 2. Uniqueness checks (via [`UserRepository`])
//! 3. Password hashing  (via [`PasswordHasher`])
//! 4. JWT-secret generation
//! 5. Persistence       (via [`UserRepository`])
//! 6. Session teardown  on password change, deactivation and deletion
//!    (via [`TokenRevocationService`])
//!
//! All storage access goes through the [`UserRepository`] port, so the
//! service has no knowledge of the underlying database.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    config::PasswordPolicy,
    credentials::{PasswordHasher, validate_password},
    error::AuthError,
    token::{RevocationReason, TokenRevocationService},
    user::{
        model::{NewUser, RegisterUser, UpdateUser, User, UserUpdate, UserWithRoles},
        repository::UserRepository,
        service::UserService,
        validation::{normalize_email, validate_email},
    },
};

/// Default implementation of [`UserService`].
///
/// ```rust,ignore
/// let users = UserServiceImpl::new(user_repo, hasher, revocation, config.password.clone());
/// ```
pub struct UserServiceImpl {
    user_repo: Arc<dyn UserRepository>,
    hasher: Arc<dyn PasswordHasher>,
    revocation: Arc<dyn TokenRevocationService>,
    policy: PasswordPolicy,
}

impl UserServiceImpl {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        hasher: Arc<dyn PasswordHasher>,
        revocation: Arc<dyn TokenRevocationService>,
        policy: PasswordPolicy,
    ) -> Self {
        Self {
            user_repo,
            hasher,
            revocation,
            policy,
        }
    }
}

#[async_trait]
impl UserService for UserServiceImpl {
    /// Register a new user account.
    ///
    /// ```text
    /// RegisterUser
    ///       ├─ 0. normalize_email()
    ///       ├─ 1. validate_email()          → AuthError::InvalidEmail
    ///       ├─ 2. validate_password()       → AuthError::WeakPassword
    ///       ├─ 3. repo.exists_by_email()    → AuthError::EmailAlreadyTaken
    ///       ├─ 4. repo.exists_by_username() → AuthError::UsernameAlreadyTaken
    ///       ├─ 5. hasher.hash()             → AuthError::HashingError
    ///       ├─ 6. repo.create(NewUser)      → AuthError::Storage
    ///       └─ User (no roles)
    /// ```
    async fn register(&self, req: RegisterUser) -> Result<User, AuthError> {
        let email = normalize_email(&req.email);
        validate_email(&email)?;
        validate_password(&req.password, &self.policy)?;

        if self.user_repo.exists_by_email(&email).await? {
            return Err(AuthError::EmailAlreadyTaken);
        }

        if let Some(ref username) = req.username
            && self.user_repo.exists_by_username(username).await?
        {
            return Err(AuthError::UsernameAlreadyTaken);
        }

        let password_hash = self.hasher.hash(&req.password)?;

        let new_user = NewUser {
            email,
            password_hash,
            username: req.username,
            first_name: req.first_name,
            last_name: req.last_name,
        };

        self.user_repo.create(new_user).await
    }

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        self.user_repo.find_by_id(user_id).await
    }
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        self.user_repo.find_by_email(&normalize_email(email)).await
    }
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        self.user_repo.find_by_username(username).await
    }
    async fn find_with_roles_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.user_repo.find_with_roles_by_id(user_id).await
    }
    async fn find_with_roles_by_email(
        &self,
        email: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.user_repo
            .find_with_roles_by_email(&normalize_email(email))
            .await
    }
    async fn find_with_roles_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserWithRoles>, AuthError> {
        self.user_repo.find_with_roles_by_username(username).await
    }

    /// Validate every supplied field, re-check uniqueness against *other*
    /// users, hash a new password, then hand a [`UserUpdate`] to the repo.
    /// A password change then ends every session of the user.
    async fn update(
        &self,
        user_id: Uuid,
        mut update: UpdateUser,
    ) -> Result<Option<User>, AuthError> {
        update.email = update.email.as_deref().map(normalize_email);
        if let Some(ref email) = update.email {
            validate_email(email)?;
            if let Some(other) = self.user_repo.find_by_email(email).await?
                && other.id != user_id
            {
                return Err(AuthError::EmailAlreadyTaken);
            }
        }

        if let Some(ref username) = update.username
            && let Some(other) = self.user_repo.find_by_username(username).await?
            && other.id != user_id
        {
            return Err(AuthError::UsernameAlreadyTaken);
        }

        let password_hash = match update.password {
            Some(ref password) => {
                validate_password(password, &self.policy)?;
                Some(self.hasher.hash(password)?)
            }
            None => None,
        };

        let password_changed = password_hash.is_some();
        let repo_update = UserUpdate {
            email: update.email,
            password_hash,
            username: update.username,
            first_name: update.first_name,
            last_name: update.last_name,
            avatar_url: update.avatar_url,
        };

        // Mutate first, then revoke: once the new hash is stored nobody can
        // log in with the old password, so every surviving session predates it.
        let updated = self.user_repo.update(user_id, repo_update).await?;
        if updated.is_some() && password_changed {
            self.revocation
                .end_all_for_user(user_id, RevocationReason::PasswordChanged)
                .await?;
        }
        Ok(updated)
    }

    /// The session rows go with the user (cascade); revoking still publishes
    /// a user-wide denylist entry for the access tokens already issued.
    async fn delete(&self, user_id: Uuid) -> Result<Option<Uuid>, AuthError> {
        let deleted = self.user_repo.delete(user_id).await?;
        if deleted.is_some() {
            self.revocation
                .end_all_for_user(user_id, RevocationReason::AccountDeleted)
                .await?;
        }
        Ok(deleted)
    }
    async fn activate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        self.user_repo.activate(user_id).await
    }
    async fn deactivate(&self, user_id: Uuid) -> Result<bool, AuthError> {
        let deactivated = self.user_repo.deactivate(user_id).await?;
        if deactivated {
            self.revocation
                .end_all_for_user(user_id, RevocationReason::AccountDisabled)
                .await?;
        }
        Ok(deactivated)
    }
}
