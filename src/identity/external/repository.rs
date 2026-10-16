//! External identity repository port.

use async_trait::async_trait;
use uuid::Uuid;

use crate::identity::external::model::{ExternalIdentity, NewExternalIdentity};
use crate::utils::error::AuthError;

/// Persistence contract for linked external identities.
///
/// Deleting a user must delete their identities.  Map driver errors to
/// [`AuthError::Storage`].
#[async_trait]
pub trait ExternalIdentityRepository: Send + Sync {
    /// The identity with this `(issuer, subject)`, compared exactly.
    async fn find_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<ExternalIdentity>, AuthError>;

    async fn find(&self, id: Uuid) -> Result<Option<ExternalIdentity>, AuthError>;

    /// A user's identities, oldest first.
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, AuthError>;

    /// Insert a link; `created_at` comes from the store.  An existing
    /// `(issuer, subject)` is [`AuthError::ExternalIdentityLinkedElsewhere`].
    async fn create(&self, new: NewExternalIdentity) -> Result<ExternalIdentity, AuthError>;

    /// Returns `false` if no such identity exists.
    async fn delete(&self, id: Uuid) -> Result<bool, AuthError>;

    /// Set `last_login_at` to now.
    async fn record_login(&self, id: Uuid) -> Result<(), AuthError>;
}
