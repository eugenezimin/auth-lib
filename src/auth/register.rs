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

use crate::auth::password;
use crate::interfaces::auth::AuthService;
use crate::interfaces::db::role_repo::RoleRepo;
use crate::interfaces::db::user_repo::UserRepo;
use crate::model::user::{NewUser, RegisterRequest, RegisterResponse};
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
}

impl AuthServiceImpl {
    pub fn new(user_repo: Arc<dyn UserRepo>, role_repo: Arc<dyn RoleRepo>) -> Self {
        Self {
            user_repo,
            role_repo,
        }
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
    ///       └─ RegisterResponse { user_id, email, username }
    /// ```
    async fn register(&self, req: RegisterRequest) -> Result<RegisterResponse, AuthError> {
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

        Ok(RegisterResponse {
            user_id: user.id,
            email: user.email,
            username: user.username,
        })
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

/// Minimum password strength requirements.
fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::WeakPassword(
            "must be at least 8 characters".into(),
        ));
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthError::WeakPassword(
            "must contain at least one uppercase letter".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::WeakPassword(
            "must contain at least one digit".into(),
        ));
    }
    Ok(())
}
