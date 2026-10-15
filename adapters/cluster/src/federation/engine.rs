//! The sync engine of one instance (federation mode).
//!
//! - **Pull.**  The instance that owns the link to another cluster learns
//!   that cluster's feed head with every link heartbeat; when it is ahead
//!   of the stored cursor, it pulls pages and applies them.
//! - **Apply.**  Records merge with the lattice rules of [`merge`](super::merge); only
//!   real changes are written (so nothing bounces back), and each change
//!   has its in-memory effects: denylist, key ring, catalog, ending the
//!   local sessions of a revoked or deactivated user.
//! - **Serve.**  Other clusters pull this database's feed and fetch single
//!   sessions through it.
//! - **Refresh gate.**  Staleness guard and pull-on-miss for refreshes on
//!   services other than the authority.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::{ClusterSettings, SessionDistribution};
use crate::constants::{FEDERATION_MERGE_ATTEMPTS, FEDERATION_PROTOCOL_VERSION};
use crate::federation::fork::ForkParams;
use crate::federation::membership::FederationClusterService;
use crate::federation::membership::SyncHooks;
use crate::federation::merge::{MergeParams, merge_session};
use crate::federation::store::SyncStore;
use crate::shared::ClusterMessage;
use crate::shared::model::SyncHead;
use crate::sync::{
    AccountSnapshot, ApplyOutcome, CatalogSnapshot, SessionAggregate, SiteId, SyncMessage,
    SyncRecord,
};
use z_auth::conf::config::AuthConfig;
use z_auth::eventing::DomainEvent;
use z_auth::security::authentication::gate::RefreshGate;
use z_auth::security::authorization::catalog::CatalogCache;
use z_auth::security::authorization::service::PermissionService;
use z_auth::security::session::RevocationReason;
use z_auth::security::session::SessionStatus;
use z_auth::security::token::denylist::Denylist;
use z_auth::security::token::keyring::KeyRing;
use z_auth::security::token::model::{
    KeyStatus, Revocation, RevocationScope, RevocationStatus, VerifyingKeyRecord,
};
use z_auth::security::token::service::TokenRevocationService;
use z_auth::utils::clock::Clock;
use z_auth::utils::error::AuthError;

/// Pages pulled from one cluster per heartbeat.
const PULL_PAGES_PER_ROUND: usize = 20;

/// Namespaces of the revocation ids every cluster derives identically.
const NS_SESSION_END: Uuid = Uuid::from_u128(0x6a1e_0c2b_4d3f_4f0e_9a51_0001_0000_0001);
const NS_FORK_LOSER: Uuid = Uuid::from_u128(0x6a1e_0c2b_4d3f_4f0e_9a51_0001_0000_0002);

fn chrono(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

/// The settings every cluster must agree on, hashed.  A peer with a
/// different fingerprint would merge differently: federation with it is
/// refused.
pub fn config_fingerprint(config: &AuthConfig, settings: &ClusterSettings) -> String {
    let r = &settings.federation;
    let line = format!(
        "v{FEDERATION_PROTOCOL_VERSION}|grace={:?}|match={:?}|skew={:?}|history={}|authz={:?}|authority={:?}|fork={:?}",
        config.session.refresh_grace,
        config.session.retry_match,
        settings.cluster.max_skew,
        config.session.history_size,
        config.authz.mode,
        r.authority_service,
        r.fork,
    );
    Sha256::digest(line.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What the engine did since it started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FederationReport {
    pub pulled: u64,
    pub applied: u64,
    pub dropped: u64,
    pub benign_forks: u64,
    pub sessions_ended: u64,
    /// Clusters whose settings differ (federation with them is refused).
    pub refused: Vec<String>,
}

pub struct FederationEngine {
    store: Arc<dyn SyncStore>,
    cluster: Arc<FederationClusterService>,
    denylist: Arc<Denylist>,
    keyring: Arc<KeyRing>,
    catalog: Arc<CatalogCache>,
    permissions: Arc<dyn PermissionService>,
    revocation: Arc<dyn TokenRevocationService>,
    clock: Arc<dyn Clock>,
    params: MergeParams,
    authority: String,
    is_authority: bool,
    distribution: SessionDistribution,
    max_staleness: Option<Duration>,
    purge_horizon: chrono::Duration,
    page_size: u32,
    entry_ttl: chrono::Duration,
    max_skew: chrono::Duration,
    node_id: Uuid,
    fingerprint: String,
    catalog_target: AtomicU64,
    report: Mutex<FederationReport>,
    /// The authority: produces a missing account snapshot on demand.
    producer: std::sync::OnceLock<Arc<crate::federation::producer::SnapshotProducer>>,
}

impl FederationEngine {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &AuthConfig,
        settings: &ClusterSettings,
        store: Arc<dyn SyncStore>,
        cluster: Arc<FederationClusterService>,
        denylist: Arc<Denylist>,
        keyring: Arc<KeyRing>,
        catalog: Arc<CatalogCache>,
        permissions: Arc<dyn PermissionService>,
        revocation: Arc<dyn TokenRevocationService>,
        clock: Arc<dyn Clock>,
        entry_ttl: Duration,
        node_id: Uuid,
    ) -> Result<Self, AuthError> {
        let r = &settings.federation;
        let authority = r
            .authority_service
            .clone()
            .ok_or_else(|| AuthError::Config("missing AUTH_AUTHORITY_SERVICE".into()))?;
        Ok(Self {
            is_authority: settings.cluster.service == authority,
            authority,
            store,
            cluster,
            denylist,
            keyring,
            catalog,
            permissions,
            revocation,
            clock,
            params: MergeParams {
                fork: ForkParams {
                    retry_match: config.session.retry_match,
                    window: chrono(r.fork.window) + chrono(settings.cluster.max_skew),
                    max_benign: r.fork.max_benign,
                    budget_window: chrono(r.fork.budget_window),
                },
                history_size: config.session.history_size,
            },
            distribution: r.session_distribution,
            max_staleness: r.max_staleness,
            purge_horizon: chrono(r.purge_horizon),
            page_size: r.pull_page_size,
            entry_ttl: chrono(entry_ttl),
            max_skew: chrono(settings.cluster.max_skew),
            node_id,
            fingerprint: config_fingerprint(config, settings),
            catalog_target: AtomicU64::new(0),
            report: Mutex::new(FederationReport::default()),
            producer: std::sync::OnceLock::new(),
        })
    }

    pub(crate) fn set_producer(
        &self,
        producer: Arc<crate::federation::producer::SnapshotProducer>,
    ) {
        let _ = self.producer.set(producer);
    }

    pub fn is_authority(&self) -> bool {
        self.is_authority
    }

    pub fn report(&self) -> FederationReport {
        self.report
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn count(&self, f: impl FnOnce(&mut FederationReport)) {
        f(&mut self.report.lock().unwrap_or_else(|e| e.into_inner()));
    }

    /// Startup: create the database identity (turns on the feed) and, on
    /// a session store, load the catalog snapshot into memory.
    pub async fn start(&self) -> Result<SiteId, AuthError> {
        let site = self.store.site_id().await?;
        if !self.is_authority
            && let Some(snapshot) = self.store.load_catalog().await?
        {
            self.catalog.replace(snapshot.catalog);
        }
        Ok(site)
    }

    /// One round: catch up with a catalog version announced earlier (the
    /// event can arrive before the snapshot).
    pub async fn tick(&self) -> Result<(), AuthError> {
        if self.catalog.version() < self.catalog_target.load(Ordering::SeqCst) {
            self.permissions.reload_catalog().await?;
        }
        Ok(())
    }

    // ── applying ────────────────────────────────────────────────────────────

    /// Merge one record from another cluster into this database.  `hold`:
    /// store a session even in on-demand mode (it was asked for).
    pub async fn apply(&self, record: SyncRecord, hold: bool) -> Result<ApplyOutcome, AuthError> {
        let outcome = match record {
            SyncRecord::Session(aggregate) => self.apply_session(*aggregate, hold).await?,
            SyncRecord::Revocation(r) => self.apply_revocation(r).await?,
            SyncRecord::VerifyingKey(k) => self.apply_key(k).await?,
            SyncRecord::Account(a) => self.apply_account(a).await?,
            SyncRecord::Catalog(c) => self.apply_catalog(*c).await?,
        };
        self.count(|r| match outcome {
            ApplyOutcome::Applied => r.applied += 1,
            ApplyOutcome::Dropped => r.dropped += 1,
            _ => {}
        });
        Ok(outcome)
    }

    async fn apply_session(
        &self,
        incoming: SessionAggregate,
        hold: bool,
    ) -> Result<ApplyOutcome, AuthError> {
        let now = self.clock.now();
        let s = &incoming.session;
        let purgeable_since = s
            .idle_expires_at
            .min(s.absolute_expires_at)
            .min(s.ended_at.unwrap_or(DateTime::<Utc>::MAX_UTC));
        if purgeable_since < now - self.purge_horizon {
            return Ok(ApplyOutcome::Dropped);
        }
        for _ in 0..FEDERATION_MERGE_ATTEMPTS {
            let local = self.store.load_session(s.id).await?;
            if local.is_none()
                && !hold
                && !self.is_authority
                && self.distribution == SessionDistribution::OnDemand
            {
                return Ok(ApplyOutcome::Dropped);
            }
            let (local_agg, rev) = match local {
                Some((agg, rev)) => (Some(agg), Some(rev)),
                None => (None, None),
            };
            let merge = merge_session(local_agg.as_ref(), &incoming, &self.params);
            if !merge.changed {
                return Ok(ApplyOutcome::Unchanged);
            }
            match self.store.store_session(&merge.merged, rev).await? {
                ApplyOutcome::Conflict => continue, // a local write won: merge again
                ApplyOutcome::Applied => {
                    self.after_session_merge(
                        &merge.merged,
                        merge.newly_ended,
                        &merge.new_benign_forks,
                    )
                    .await?;
                    return Ok(ApplyOutcome::Applied);
                }
                other => return Ok(other),
            }
        }
        Ok(ApplyOutcome::Conflict)
    }

    async fn after_session_merge(
        &self,
        merged: &SessionAggregate,
        newly_ended: bool,
        benign: &[crate::federation::fork::BenignFork],
    ) -> Result<(), AuthError> {
        let s = &merged.session;
        if newly_ended && s.status != SessionStatus::Active {
            // Every cluster derives this same revocation, so tokens of a
            // session ended elsewhere stop working here at once — even ones
            // minted during the lag, which a user-wide cutoff would miss.
            let revocation = self.derived(
                Uuid::new_v5(&NS_SESSION_END, s.id.as_bytes()),
                RevocationScope::Session(s.id),
                s.end_reason.unwrap_or(RevocationReason::Administrative),
                s.ended_at.unwrap_or_else(|| self.clock.now()),
            );
            self.publish_revocation(revocation).await?;
            self.count(|r| r.sessions_ended += 1);
        }
        for fork in benign {
            self.count(|r| r.benign_forks += 1);
            for loser in &fork.losers {
                let revocation = self.derived(
                    Uuid::new_v5(&NS_FORK_LOSER, loser.as_bytes()),
                    RevocationScope::Token(*loser),
                    RevocationReason::ConcurrentRefresh,
                    fork.at,
                );
                self.publish_revocation(revocation).await?;
            }
        }
        Ok(())
    }

    fn derived(
        &self,
        id: Uuid,
        scope: RevocationScope,
        reason: RevocationReason,
        at: DateTime<Utc>,
    ) -> Revocation {
        Revocation {
            id,
            scope,
            reason,
            status: RevocationStatus::Pending,
            origin_node: self.node_id,
            revoked_at: at,
            expires_at: at.max(self.clock.now()) + self.entry_ttl,
            enforced_at: None,
            enforced_by: None,
        }
    }

    /// Store a revocation, deny it here, and tell the other instances.
    async fn publish_revocation(&self, revocation: Revocation) -> Result<(), AuthError> {
        self.store.merge_revocation(&revocation).await?;
        if self.denylist.apply(&revocation) {
            self.cluster.publish(DomainEvent::Revoked(revocation)).await;
        }
        Ok(())
    }

    async fn apply_revocation(&self, r: Revocation) -> Result<ApplyOutcome, AuthError> {
        if r.expires_at <= self.clock.now() {
            return Ok(ApplyOutcome::Dropped);
        }
        let outcome = self.store.merge_revocation(&r).await?;
        if outcome == ApplyOutcome::Applied {
            self.denylist.apply(&r);
            let event = if r.status == RevocationStatus::Enforced {
                DomainEvent::RevocationEnforced(r.clone())
            } else {
                DomainEvent::Revoked(r.clone())
            };
            self.cluster.publish(event).await;
            if let RevocationScope::User(user) = r.scope {
                // A user-wide revocation ends this cluster's sessions of that
                // user that already existed then.
                self.end_user_sessions(user, Some(r.revoked_at + self.max_skew), r.reason)
                    .await?;
            }
        }
        Ok(outcome)
    }

    async fn end_user_sessions(
        &self,
        user: Uuid,
        created_before: Option<DateTime<Utc>>,
        reason: RevocationReason,
    ) -> Result<(), AuthError> {
        for sid in self.store.active_session_ids(user).await? {
            let Some((aggregate, _)) = self.store.load_session(sid).await? else {
                continue;
            };
            if created_before.is_none_or(|cutoff| aggregate.session.created_at <= cutoff)
                && self.revocation.end_session(sid, reason).await?
            {
                self.count(|r| r.sessions_ended += 1);
            }
        }
        Ok(())
    }

    async fn apply_key(&self, k: VerifyingKeyRecord) -> Result<ApplyOutcome, AuthError> {
        let outcome = self.store.merge_key(&k).await?;
        if outcome == ApplyOutcome::Applied {
            self.keyring.merge(k.clone());
            let event = if k.status == KeyStatus::Revoked {
                DomainEvent::SigningKeyRevoked { kid: k.kid }
            } else {
                DomainEvent::VerifyingKeyPublished(k)
            };
            self.cluster.publish(event).await;
        }
        Ok(outcome)
    }

    async fn apply_account(&self, a: AccountSnapshot) -> Result<ApplyOutcome, AuthError> {
        let outcome = self.store.apply_account(&a).await?;
        if outcome == ApplyOutcome::Applied && (a.deleted || !a.is_active) {
            let reason = if a.deleted {
                RevocationReason::AccountDeleted
            } else {
                RevocationReason::AccountDisabled
            };
            self.end_user_sessions(a.user_id, None, reason).await?;
        }
        Ok(outcome)
    }

    async fn apply_catalog(&self, c: CatalogSnapshot) -> Result<ApplyOutcome, AuthError> {
        let version = c.version;
        let outcome = self.store.apply_catalog(&c).await?;
        if outcome == ApplyOutcome::Applied {
            self.catalog_target.fetch_max(version, Ordering::SeqCst);
            if !self.is_authority {
                self.catalog.replace(c.catalog);
            }
            self.cluster
                .publish(DomainEvent::CatalogChanged { version })
                .await;
        }
        Ok(outcome)
    }

    // ── pulling ─────────────────────────────────────────────────────────────

    async fn pull(&self, cluster: &str, head: &SyncHead) -> Result<(), AuthError> {
        let site = SiteId(head.site_id);
        let mut cursor = self.store.cursor(site).await?;
        for _ in 0..PULL_PAGES_PER_ROUND {
            if (cursor.txid, cursor.seq) >= head.head {
                break;
            }
            let request = ClusterMessage::Sync(Box::new(SyncMessage::Pull {
                after: cursor,
                limit: self.page_size,
            }));
            let Some(ClusterMessage::Sync(reply)) = self.cluster.deliver(cluster, request).await?
            else {
                return Err(AuthError::ClusterMessageRejected(
                    "expected a feed page".into(),
                ));
            };
            let SyncMessage::Page(page) = *reply else {
                return Err(AuthError::ClusterMessageRejected(
                    "expected a feed page".into(),
                ));
            };
            if page.site != site {
                return Err(AuthError::ClusterMessageRejected(format!(
                    "cluster {cluster} answered for another database"
                )));
            }
            let pulled = page.records.len() as u64;
            for record in page.records {
                self.apply(record, false).await?;
            }
            self.count(|r| r.pulled += pulled);
            if page.next <= cursor {
                break; // nothing more is safe to read yet
            }
            cursor = page.next;
            self.store.advance_cursor(site, cursor).await?;
            if !page.more {
                break;
            }
        }
        if cluster == self.authority && (cursor.txid, cursor.seq) >= head.head {
            self.store
                .record_caught_up(&self.authority, self.clock.now())
                .await?;
        }
        Ok(())
    }

    /// Fetch one session (and its user's account) from `cluster`.
    async fn fetch_from(
        &self,
        cluster: &str,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, AuthError> {
        let request = ClusterMessage::Sync(Box::new(SyncMessage::FetchSession {
            session_id,
            user_id,
        }));
        let Some(ClusterMessage::Sync(reply)) = self.cluster.deliver(cluster, request).await?
        else {
            return Ok(false);
        };
        let SyncMessage::SessionState { session, account } = *reply else {
            return Ok(false);
        };
        let mut arrived = false;
        if let Some(account) = account {
            arrived |=
                self.apply(SyncRecord::Account(account), true).await? == ApplyOutcome::Applied;
        }
        if let Some(session) = session {
            arrived |=
                self.apply(SyncRecord::Session(session), true).await? == ApplyOutcome::Applied;
        }
        Ok(arrived)
    }
}

#[async_trait]
impl SyncHooks for FederationEngine {
    async fn head(&self) -> Option<SyncHead> {
        let site = self.store.site_id().await.ok()?;
        let head = self.store.head().await.ok()?;
        Some(SyncHead {
            site_id: site.0,
            head: (head.txid, head.seq),
            protocol: FEDERATION_PROTOCOL_VERSION,
            config_fingerprint: self.fingerprint.clone(),
        })
    }

    async fn on_remote(&self, cluster: &str, head: &SyncHead) {
        if head.protocol != FEDERATION_PROTOCOL_VERSION
            || head.config_fingerprint != self.fingerprint
        {
            self.count(|r| {
                if !r.refused.iter().any(|c| c == cluster) {
                    r.refused.push(cluster.to_string());
                }
            });
            return;
        }
        // Errors are retried with the next heartbeat.
        let _ = self.pull(cluster, head).await;
    }

    async fn handle(&self, message: SyncMessage) -> Result<Option<SyncMessage>, AuthError> {
        match message {
            SyncMessage::Pull { after, limit } => {
                let limit = limit.clamp(1, self.page_size.max(1));
                Ok(Some(SyncMessage::Page(
                    self.store.changes_since(after, limit).await?,
                )))
            }
            SyncMessage::FetchSession {
                session_id,
                user_id,
            } => {
                let session = self
                    .store
                    .load_session(session_id)
                    .await?
                    .map(|(a, _)| Box::new(a));
                let mut account = self.store.load_account(user_id).await?;
                if account.is_none()
                    && let Some(producer) = self.producer.get()
                {
                    // Sessions from before federation mode have no snapshot yet.
                    producer.account_changed(user_id).await?;
                    account = self.store.load_account(user_id).await?;
                }
                Ok(Some(SyncMessage::SessionState { session, account }))
            }
            SyncMessage::Page(_) | SyncMessage::SessionState { .. } => Err(
                AuthError::ClusterMessageRejected("reply sent as a request".into()),
            ),
        }
    }
}

#[async_trait]
impl RefreshGate for FederationEngine {
    async fn check_fresh(&self) -> Result<(), AuthError> {
        let Some(max) = self.max_staleness.filter(|_| !self.is_authority) else {
            return Ok(());
        };
        match self.store.caught_up_at(&self.authority).await? {
            Some(at) if self.clock.now() - at <= chrono(max) => Ok(()),
            _ => Err(AuthError::ReplicaStale),
        }
    }

    async fn catch_up(&self, session_id: Uuid, user_id: Uuid) -> Result<bool, AuthError> {
        if self.is_authority {
            return Ok(false); // every session starts here
        }
        // The authority first (every session starts there), then the rest.
        let mut clusters = vec![self.authority.clone()];
        clusters.extend(
            self.cluster
                .remote_clusters()
                .into_iter()
                .filter(|c| *c != self.authority),
        );
        let mut arrived = false;
        for cluster in clusters {
            if self.cluster.is_cluster_dead(&cluster) {
                continue;
            }
            if let Ok(found) = self.fetch_from(&cluster, session_id, user_id).await {
                arrived |= found;
                if found {
                    break;
                }
            }
        }
        Ok(arrived)
    }
}
