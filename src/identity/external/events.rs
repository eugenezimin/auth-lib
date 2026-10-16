//! Notifications about linked identities, e.g. to email the user that a new
//! sign-in method was added.

use async_trait::async_trait;

use crate::identity::external::model::ExternalIdentity;

/// Told about every link and unlink, after it is stored.  Best effort: the
/// operation has already succeeded, so implementations handle their own
/// failures.
#[async_trait]
pub trait ExternalIdentityEvents: Send + Sync {
    async fn linked(&self, _identity: &ExternalIdentity) {}
    async fn unlinked(&self, _identity: &ExternalIdentity) {}
}

/// Drops every notification.
pub struct NoopExternalIdentityEvents;

impl ExternalIdentityEvents for NoopExternalIdentityEvents {}
