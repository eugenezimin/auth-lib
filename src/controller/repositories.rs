//! [`Repositories`] — the storage every z-auth instance needs.

use std::sync::Arc;

use crate::identity::access::{RoleRepository, UserRoleRepository};
use crate::identity::user::UserRepository;
use crate::security::session::SessionRepository;
use crate::security::token::{KeyRepository, RevocationRepository};

/// The storage every instance needs.  Every field is required, so a missing
/// repository is a compile error rather than a startup failure.
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use z_auth::Repositories;
/// # fn missing(users: Arc<dyn z_auth::identity::user::UserRepository>) {
/// let repos = Repositories { users }; // roles, user_roles, sessions, … missing
/// # }
/// ```
#[derive(Clone)]
pub struct Repositories {
    pub users: Arc<dyn UserRepository>,
    pub roles: Arc<dyn RoleRepository>,
    pub user_roles: Arc<dyn UserRoleRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub revocations: Arc<dyn RevocationRepository>,
    /// Published verifying keys (unused without the `crypto` feature).
    pub keys: Arc<dyn KeyRepository>,
}
