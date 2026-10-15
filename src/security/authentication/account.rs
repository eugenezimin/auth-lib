//! Where a refresh reads the account it re-checks: whether the user may
//! still refresh, and the authorization data for the new access token.
//!
//! - [`StoreAccountSource`] (standalone, shared, and the authority in
//!   federation mode) reads the user, roles and grants from the store.
//! - In federation mode the other services read the account snapshot the
//!   authority pushed (`z_auth_cluster::federation::guard::SnapshotAccountSource`),
//!   installed by that extension.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::identity::user::repository::UserRepository;
use crate::security::authorization::service::AuthzClaimsProvider;
use crate::security::token::model::AuthzClaims;
use crate::utils::error::AuthError;

/// What a refresh needs to know about the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshAccount {
    pub is_active: bool,
    /// Authorization data for the new token; `None` when inactive or when
    /// the authorization mode puts nothing into tokens.
    pub authz: Option<AuthzClaims>,
}

#[async_trait]
pub trait RefreshAccountSource: Send + Sync {
    /// `Ok(None)` if the user no longer exists.
    async fn load(&self, user_id: Uuid) -> Result<Option<RefreshAccount>, AuthError>;
}

/// Reads the account from the user, role and permission repositories.
pub struct StoreAccountSource {
    users: Arc<dyn UserRepository>,
    authz: Arc<dyn AuthzClaimsProvider>,
}

impl StoreAccountSource {
    pub fn new(users: Arc<dyn UserRepository>, authz: Arc<dyn AuthzClaimsProvider>) -> Self {
        Self { users, authz }
    }
}

#[async_trait]
impl RefreshAccountSource for StoreAccountSource {
    async fn load(&self, user_id: Uuid) -> Result<Option<RefreshAccount>, AuthError> {
        let Some(account) = self.users.find_with_roles_by_id(user_id).await? else {
            return Ok(None);
        };
        if !account.user.is_active {
            return Ok(Some(RefreshAccount {
                is_active: false,
                authz: None,
            }));
        }
        Ok(Some(RefreshAccount {
            is_active: true,
            authz: self.authz.claims_for(&account).await?,
        }))
    }
}
