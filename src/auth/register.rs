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
}

impl AuthServiceImpl {
    pub fn new(user_repo: Arc<dyn UserRepo>) -> Self {
        Self { user_repo }
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

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── email validation ──────────────────────────────────────────────────────

    #[test]
    fn valid_emails_pass() {
        for email in ["user@example.com", "a.b+tag@sub.domain.io"] {
            assert!(validate_email(email).is_ok(), "should accept: {email}");
        }
    }

    #[test]
    fn invalid_emails_are_rejected() {
        for email in ["notanemail", "@nodomain", "no-at-sign", "missing@dot"] {
            assert!(validate_email(email).is_err(), "should reject: {email}");
        }
    }

    // ── password validation ───────────────────────────────────────────────────

    #[test]
    fn strong_password_passes() {
        assert!(validate_password("Secure1!").is_ok());
    }

    #[test]
    fn short_password_is_rejected() {
        assert!(matches!(
            validate_password("Ab1"),
            Err(AuthError::WeakPassword(_))
        ));
    }

    #[test]
    fn no_uppercase_is_rejected() {
        assert!(matches!(
            validate_password("alllower1"),
            Err(AuthError::WeakPassword(_))
        ));
    }

    #[test]
    fn no_digit_is_rejected() {
        assert!(matches!(
            validate_password("NoDigitsHere"),
            Err(AuthError::WeakPassword(_))
        ));
    }

    // ── register flow (mock repo) ─────────────────────────────────────────────

    use crate::model::user::User;
    use async_trait::async_trait;
    use std::sync::Arc;

    struct AlwaysFreeRepo;

    #[async_trait]
    impl UserRepo for AlwaysFreeRepo {
        async fn find_by_email(&self, _: &str) -> Result<Option<User>, AuthError> {
            Ok(None)
        }
        async fn exists_by_email(&self, _: &str) -> Result<bool, AuthError> {
            Ok(false)
        }
        async fn exists_by_username(&self, _: &str) -> Result<bool, AuthError> {
            Ok(false)
        }
        async fn create(&self, new_user: NewUser) -> Result<User, AuthError> {
            Ok(User {
                id: Uuid::new_v4(),
                email: new_user.email,
                password_hash: Some(new_user.password_hash),
                jwt_secret: Some(new_user.jwt_secret),
                username: new_user.username,
                first_name: new_user.first_name,
                last_name: new_user.last_name,
                avatar_url: None,
                is_active: true,
                is_verified: false,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
        }
    }

    struct EmailTakenRepo;

    #[async_trait]
    impl UserRepo for EmailTakenRepo {
        async fn find_by_email(&self, _: &str) -> Result<Option<User>, AuthError> {
            Ok(None)
        }
        async fn exists_by_email(&self, _: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
        async fn exists_by_username(&self, _: &str) -> Result<bool, AuthError> {
            Ok(false)
        }
        async fn create(&self, _: NewUser) -> Result<User, AuthError> {
            unreachable!()
        }
    }

    fn make_valid_request() -> RegisterRequest {
        RegisterRequest {
            email: "alice@example.com".into(),
            password: "Secure1pass".into(),
            username: Some("alice".into()),
            first_name: Some("Alice".into()),
            last_name: None,
        }
    }

    #[tokio::test]
    async fn successful_registration_returns_response() {
        let svc = AuthServiceImpl::new(Arc::new(AlwaysFreeRepo));
        let res = svc.register(make_valid_request()).await.unwrap();
        assert_eq!(res.email, "alice@example.com");
        assert_eq!(res.username, Some("alice".into()));
    }

    #[tokio::test]
    async fn duplicate_email_returns_email_already_taken() {
        let svc = AuthServiceImpl::new(Arc::new(EmailTakenRepo));
        let err = svc.register(make_valid_request()).await.unwrap_err();
        assert!(matches!(err, AuthError::EmailAlreadyTaken));
    }

    #[tokio::test]
    async fn invalid_email_is_caught_before_db() {
        let svc = AuthServiceImpl::new(Arc::new(AlwaysFreeRepo));
        let mut req = make_valid_request();
        req.email = "not-an-email".into();
        assert!(matches!(
            svc.register(req).await,
            Err(AuthError::InvalidEmail(_))
        ));
    }

    #[tokio::test]
    async fn weak_password_is_caught_before_db() {
        let svc = AuthServiceImpl::new(Arc::new(AlwaysFreeRepo));
        let mut req = make_valid_request();
        req.password = "weak".into();
        assert!(matches!(
            svc.register(req).await,
            Err(AuthError::WeakPassword(_))
        ));
    }
}
