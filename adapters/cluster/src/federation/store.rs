//! Sync storage port — implemented by adapters for each cluster's database
//! (the authority's full schema and the session-store schema alike).
//!
//! **The change feed.**  Every write to a synced table (sessions, their
//! generations and aliases, revocations, verifying keys, account and
//! catalog snapshots) records the record's key in the feed, in the same
//! transaction — including writes made directly in SQL.  The feed holds
//! one entry per record (its latest change), so reading it from the start
//! is a full export.  An apply that changes nothing must write nothing:
//! that is what stops changes from bouncing between clusters.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::sync::{
    AccountSnapshot, ApplyOutcome, CatalogSnapshot, ChangePage, FeedCursor, SessionAggregate,
    SiteId,
};
use z_auth::security::token::model::{Revocation, VerifyingKeyRecord};
use z_auth::utils::error::AuthError;

#[async_trait]
pub trait SyncStore: Send + Sync {
    /// This database's identity, created on first use.
    async fn site_id(&self) -> Result<SiteId, AuthError>;

    /// Position of the newest change that is safe to read.
    async fn head(&self) -> Result<FeedCursor, AuthError>;

    /// The current state of up to `limit` records that changed after
    /// `after`, in feed order.  Must never return a cursor past a change
    /// that may still commit (Postgres: only entries whose transaction is
    /// older than every running one).
    async fn changes_since(&self, after: FeedCursor, limit: u32) -> Result<ChangePage, AuthError>;

    /// A session with every variant of every generation, and its revision.
    async fn load_session(&self, id: Uuid) -> Result<Option<(SessionAggregate, u64)>, AuthError>;

    /// Replace the stored session with `merged` — only if its revision is
    /// still `expected` (`None`: it must not exist yet); otherwise
    /// [`ApplyOutcome::Conflict`].  Every local session write bumps the
    /// revision.
    async fn store_session(
        &self,
        merged: &SessionAggregate,
        expected: Option<u64>,
    ) -> Result<ApplyOutcome, AuthError>;

    /// Ids of the user's sessions that are still active.
    async fn active_session_ids(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError>;

    /// Insert a revocation (with its id) or merge it into the stored one,
    /// atomically: `enforced` wins, earliest `enforced_at` (with its
    /// `enforced_by`) and `revoked_at`, latest `expires_at`.
    async fn merge_revocation(&self, revocation: &Revocation) -> Result<ApplyOutcome, AuthError>;

    /// Insert a verifying key or merge it: `revoked` wins.
    async fn merge_key(&self, key: &VerifyingKeyRecord) -> Result<ApplyOutcome, AuthError>;

    /// Store an account snapshot if it is newer than the stored one.
    async fn apply_account(&self, account: &AccountSnapshot) -> Result<ApplyOutcome, AuthError>;

    async fn load_account(&self, user_id: Uuid) -> Result<Option<AccountSnapshot>, AuthError>;

    /// Store the catalog snapshot if it is newer.
    async fn apply_catalog(&self, catalog: &CatalogSnapshot) -> Result<ApplyOutcome, AuthError>;

    async fn load_catalog(&self) -> Result<Option<CatalogSnapshot>, AuthError>;

    /// How far this database has read another one's feed.
    async fn cursor(&self, site: SiteId) -> Result<FeedCursor, AuthError>;

    /// Move a cursor forward (never back).
    async fn advance_cursor(&self, site: SiteId, to: FeedCursor) -> Result<(), AuthError>;

    /// Forget a cursor: the next pull reads the whole feed again.
    async fn reset_cursor(&self, site: SiteId) -> Result<(), AuthError>;

    /// The next account-snapshot version (authority only; monotonic).
    async fn next_version(&self) -> Result<u64, AuthError>;

    /// This database has read everything `service` had committed, as of
    /// `at` (the staleness guard reads it back — shared by every instance
    /// of the cluster).
    async fn record_caught_up(&self, service: &str, at: DateTime<Utc>) -> Result<(), AuthError>;

    async fn caught_up_at(&self, service: &str) -> Result<Option<DateTime<Utc>>, AuthError>;
}
