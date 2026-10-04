//! sqlx → [`AuthError`] mapping, shared by every repository.

use auth_lib::AuthError;

use crate::constants::*;

/// Map a sqlx error to a domain [`AuthError`].
///
/// Unique-constraint violations (`23505`) are translated to specific
/// variants by constraint name; everything else becomes
/// [`AuthError::Storage`].
pub(crate) fn map_sqlx_error(e: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = e
        && db_err.code().as_deref() == Some(PG_UNIQUE_VIOLATION)
    {
        match db_err.constraint().unwrap_or("") {
            CONSTRAINT_USERS_EMAIL => return AuthError::EmailAlreadyTaken,
            CONSTRAINT_USERS_USERNAME => return AuthError::UsernameAlreadyTaken,
            CONSTRAINT_ROLES_NAME | CONSTRAINT_ROLES_CODE => return AuthError::RoleAlreadyExists,
            CONSTRAINT_PERMISSIONS_CODE => return AuthError::PermissionAlreadyExists,
            CONSTRAINT_USER_ROLE_ACTIVE => return AuthError::RoleAlreadyAssigned,
            _ => {}
        }
    }
    AuthError::Storage(e.to_string())
}
