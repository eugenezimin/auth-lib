//! Federation-mode [`ClusterService`]: membership of this instance's own
//! cluster (full mesh, registry in the cluster's database, eviction with
//! the registry as witness, self-fencing), and one link to every other
//! cluster with retry, circuit breaker and failover between siblings.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::future::join_all;
use uuid::Uuid;

use crate::config::ClusterConfig;
use crate::constants::{
    CLUSTER_OUTBOX_MAX_ATTEMPTS, CLUSTER_SEED_PROBE_EVERY, CLUSTER_SNAPSHOT_COOLDOWN_BEATS,
};
use crate::federation::membership::state::{
    Handover, LinkOutgoing, MeshState, Outgoing, SiblingHeard,
};
use crate::shared::EnvelopeSigner;
use crate::shared::ReplicatedMemory;
use crate::shared::model::{
    ClusterEnvelope, ClusterMessage, ClusterReport, EvictOutcome, Heartbeat, HeartbeatStatus,
    LinkStatus, NodeInfo, NodeState, NodeTransition, PeerState, Welcome,
};
use crate::shared::repository::NodeRepository;
use crate::shared::service::ClusterService;
use crate::shared::transport::{ClusterTransport, Delay};
use z_auth::eventing::{DomainEvent, EventPublisher};
use z_auth::utils::clock::Clock;
use z_auth::utils::error::AuthError;

/// Called once when this instance fences itself.  The host should restart
/// the process (a restart gets a new node id and rejoins cleanly).
pub type FenceHook = Arc<dyn Fn() + Send + Sync>;

fn rejected(reason: &str) -> AuthError {
    AuthError::ClusterMessageRejected(reason.into())
}

fn chrono(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

/// Fan-out counts.
#[derive(Default, Clone, Copy)]
struct Delivery {
    sent: usize,
    failed: usize,
}

impl std::ops::AddAssign for Delivery {
    fn add_assign(&mut self, other: Self) {
        self.sent += other.sent;
        self.failed += other.failed;
    }
}

pub struct FederationClusterService {
    state: Arc<MeshState>,
    hooks: OnceLock<Weak<dyn super::SyncHooks>>,
    signer: EnvelopeSigner,
    transport: Arc<dyn ClusterTransport>,
    delay: Arc<dyn Delay>,
    nodes: Arc<dyn NodeRepository>,
    memory: ReplicatedMemory,
    clock: Arc<dyn Clock>,
    config: ClusterConfig,
    /// Self-fencing enabled (`AUTH_CLUSTER_SELF_FENCE=quorum`).
    fencing: bool,
    on_fenced: Option<FenceHook>,
    ticks: AtomicU64,
}

impl FederationClusterService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        state: Arc<MeshState>,
        signer: EnvelopeSigner,
        transport: Arc<dyn ClusterTransport>,
        delay: Arc<dyn Delay>,
        nodes: Arc<dyn NodeRepository>,
        memory: ReplicatedMemory,
        config: &ClusterConfig,
        fencing: bool,
        on_fenced: Option<FenceHook>,
    ) -> Self {
        Self {
            state,
            hooks: OnceLock::new(),
            signer,
            transport,
            delay,
            nodes,
            clock: memory.clock.clone(),
            memory,
            config: config.clone(),
            fencing,
            on_fenced,
            ticks: AtomicU64::new(0),
        }
    }

    /// Plug in the federation engine.
    pub(crate) fn set_hooks(&self, hooks: &Arc<dyn super::SyncHooks>) {
        let _ = self.hooks.set(Arc::downgrade(hooks));
    }

    fn hooks(&self) -> Option<Arc<dyn super::SyncHooks>> {
        self.hooks.get().and_then(Weak::upgrade)
    }

    /// This instance's service name (its cluster).
    pub fn service(&self) -> String {
        self.state.local().service
    }

    /// `host:port` of the known instances of `cluster`.
    pub fn addresses_of(&self, cluster: &str) -> Vec<String> {
        let local = self.state.local();
        let mut members: Vec<NodeInfo> = if cluster == local.service {
            std::iter::once(local)
                .chain(self.state.siblings().into_iter().map(|s| s.info))
                .collect()
        } else {
            self.state
                .remote_members(cluster)
                .into_iter()
                .map(|m| m.info)
                .collect()
        };
        members.sort_by_key(|m| m.node_id);
        members
            .into_iter()
            .map(|m| format!("{}:{}", m.host(), m.port))
            .collect()
    }

    /// This instance stopped serving: evicted by its cluster or cut off
    /// from the majority of it.
    pub fn is_fenced(&self) -> bool {
        self.state.is_fenced()
    }

    /// Other clusters this instance knows about.
    pub fn remote_clusters(&self) -> Vec<String> {
        self.state.remote_clusters()
    }

    /// Every sibling failed to reach `cluster`.
    pub fn is_cluster_dead(&self, cluster: &str) -> bool {
        self.state.is_dead(cluster)
    }

    /// The instance of this cluster that owns the link to `cluster`.
    pub fn link_owner(&self, cluster: &str) -> Option<Uuid> {
        self.state.link_owner(cluster)
    }

    /// Node ids this cluster evicted.
    pub fn retired(&self) -> Vec<Uuid> {
        self.state.retired()
    }

    /// The advertised address of this running instance changed: store it,
    /// then tell the siblings directly (they do not reload the registry).
    /// Other clusters learn it with the next link heartbeat.
    pub async fn update_address(
        &self,
        ip: Option<std::net::IpAddr>,
        dns_name: Option<String>,
        port: u16,
    ) -> Result<(), AuthError> {
        let mut info = self.state.local();
        info.ip = ip;
        info.dns_name = dns_name;
        info.port = port;
        self.nodes.update_address(&info).await?;
        self.state.set_local(info.clone());
        self.broadcast_siblings(ClusterMessage::NodeUpdated(info), true)
            .await;
        Ok(())
    }

    /// Push a domain event: to every sibling, and over every link this
    /// instance owns (the other link owners forward it when it reaches
    /// them).
    pub async fn publish(&self, event: DomainEvent) {
        if self.is_fenced() {
            return;
        }
        self.broadcast_siblings(ClusterMessage::Event(event.clone()), true)
            .await;
        self.forward_across(&event).await;
    }

    /// Deliver `payload` to `cluster` through the link owner (this instance
    /// or a sibling) and return the remote reply.
    pub async fn deliver(
        &self,
        cluster: &str,
        payload: ClusterMessage,
    ) -> Result<Option<ClusterMessage>, AuthError> {
        if self.is_fenced() {
            return Err(AuthError::NodeFenced);
        }
        let unreachable = || AuthError::ClusterUnreachable(format!("cluster {cluster}"));
        let owner = self.state.link_owner(cluster).ok_or_else(unreachable)?;
        if owner == self.state.local_id() {
            return self.link_request(cluster, payload).await;
        }
        let sibling = self.state.sibling(owner).ok_or_else(unreachable)?;
        let forward = ClusterMessage::Forward {
            cluster: cluster.to_string(),
            message: Box::new(payload),
        };
        match self.send_to(&sibling.info, forward).await? {
            Some(ClusterMessage::ForwardReply(reply)) => Ok(reply.map(|r| *r)),
            _ => Err(rejected("unexpected reply to a forward")),
        }
    }

    // ── sending ─────────────────────────────────────────────────────────────

    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    fn beat(&self) -> chrono::Duration {
        chrono(self.config.heartbeat)
    }

    fn seal(&self, payload: ClusterMessage) -> Result<ClusterEnvelope, AuthError> {
        self.signer
            .seal(Uuid::new_v4(), self.state.local_id(), self.now(), payload)
    }

    fn reply(&self, payload: ClusterMessage) -> Result<Option<ClusterEnvelope>, AuthError> {
        self.seal(payload).map(Some)
    }

    /// Send one message; returns the verified reply payload.  A `Retired`
    /// reply means our own cluster evicted us: fence.
    async fn send_to(
        &self,
        to: &NodeInfo,
        payload: ClusterMessage,
    ) -> Result<Option<ClusterMessage>, AuthError> {
        let envelope = self.seal(payload)?;
        let Some(reply) = self.transport.send(to, &envelope).await? else {
            return Ok(None);
        };
        let wrong_sender = !to.node_id.is_nil() && reply.from != to.node_id;
        if wrong_sender || !self.signer.verify(&reply) {
            return Err(rejected("reply not signed by the peer"));
        }
        if matches!(reply.payload, ClusterMessage::Retired) {
            self.fence_self();
            return Err(AuthError::NodeFenced);
        }
        Ok(Some(reply.payload))
    }

    /// Send to each target concurrently; no bookkeeping.
    async fn fan_out(
        &self,
        targets: &[NodeInfo],
        payload: &ClusterMessage,
    ) -> Vec<Result<Option<ClusterMessage>, AuthError>> {
        join_all(targets.iter().map(|to| self.send_to(to, payload.clone()))).await
    }

    /// Send to every sibling.  An answer counts as hearing from it; with
    /// `retry`, failures go to the outbox.
    async fn broadcast_siblings(&self, payload: ClusterMessage, retry: bool) -> Delivery {
        let targets: Vec<NodeInfo> = self.state.siblings().into_iter().map(|s| s.info).collect();
        let results = self.fan_out(&targets, &payload).await;
        let now = self.now();
        let mut delivery = Delivery::default();
        let mut recovered = Vec::new();
        for (to, result) in targets.into_iter().zip(results) {
            match result {
                Ok(_) => {
                    delivery.sent += 1;
                    if self.state.heard_sibling(to.node_id, None, None, now)
                        == SiblingHeard::Recovered
                    {
                        recovered.push(to.node_id);
                    }
                }
                Err(_) => {
                    delivery.failed += 1;
                    if retry {
                        self.state.enqueue(Outgoing {
                            to: to.node_id,
                            payload: payload.clone(),
                            attempts: 1,
                        });
                    }
                }
            }
        }
        for id in recovered {
            self.recovered(id).await;
        }
        delivery
    }

    /// One request over the link to `cluster`: targets in order (last good
    /// one first, then random), each tried `retry_attempts` times with
    /// exponential backoff; a target that fails them all records one
    /// breaker failure.
    async fn link_request(
        &self,
        cluster: &str,
        payload: ClusterMessage,
    ) -> Result<Option<ClusterMessage>, AuthError> {
        let link = self.config.link;
        let cooldown = chrono(link.breaker_cooldown);
        for target in self.state.link_targets(cluster, self.now(), cooldown) {
            for attempt in 0..link.retry_attempts {
                match self.send_to(&target, payload.clone()).await {
                    Ok(reply) => {
                        self.state.link_success(cluster, target.node_id);
                        return Ok(reply);
                    }
                    Err(AuthError::NodeFenced) => return Err(AuthError::NodeFenced),
                    Err(_) if attempt + 1 < link.retry_attempts => {
                        let backoff = link.retry_backoff.saturating_mul(1 << attempt.min(16));
                        self.delay.sleep(backoff).await;
                    }
                    Err(_) => {}
                }
            }
            self.state
                .link_failure(cluster, target.node_id, self.now(), link.breaker_failures);
        }
        Err(AuthError::ClusterUnreachable(format!("cluster {cluster}")))
    }

    /// Forward an event over every link this instance owns.
    async fn forward_across(&self, event: &DomainEvent) {
        for cluster in self.state.remote_clusters() {
            if !self.state.owns_link(&cluster) {
                continue;
            }
            let payload = ClusterMessage::Event(event.clone());
            if self.link_request(&cluster, payload.clone()).await.is_err() {
                self.state.enqueue_link(LinkOutgoing {
                    cluster,
                    payload,
                    attempts: 1,
                });
            }
        }
    }

    // ── fencing ─────────────────────────────────────────────────────────────

    fn fence_self(&self) {
        if self.fencing
            && self.state.fence()
            && let Some(hook) = &self.on_fenced
        {
            hook();
        }
    }

    // ── membership views ────────────────────────────────────────────────────

    fn welcome(&self) -> ClusterMessage {
        ClusterMessage::Welcome(Box::new(Welcome {
            info: self.state.local(),
            members: self.state.members(),
            retired: self.state.retired(),
            directory: self.state.directory(),
            snapshot: self.memory.snapshot(),
        }))
    }

    async fn link_status(&self) -> LinkStatus {
        let sync = match self.hooks() {
            Some(hooks) => hooks.head().await,
            None => None,
        };
        LinkStatus {
            info: self.state.local(),
            members: self.state.members(),
            retired: self.state.retired(),
            directory: self.state.directory(),
            digest: self.memory.digest(),
            sync,
        }
    }

    /// Merge a `Welcome`; returns clusters that came back alive and whether
    /// the directory changed.
    async fn merge_welcome(&self, w: Welcome, now: DateTime<Utc>) -> (Vec<String>, bool) {
        let local = self.state.local();
        let mut alive = Vec::new();
        let mut directory_changed = false;
        if w.retired.contains(&local.node_id) && w.info.service == local.service {
            self.fence_self();
        }
        if w.info.service == local.service {
            self.state
                .heard_sibling(w.info.node_id, Some(w.info.clone()), None, now);
            for id in &w.retired {
                self.state.retire(*id, now);
            }
            for m in w.members {
                if m.heartbeat != HeartbeatStatus::Missing {
                    self.state.add_sibling(m.info, m.state, now);
                }
            }
        } else {
            let cluster = w.info.service.clone();
            directory_changed |= self
                .state
                .set_remote_members(&cluster, &w.members, &w.retired);
            if self.state.mark_reachable(&cluster) {
                self.state.reset_breakers(&cluster);
                alive.push(cluster);
            }
        }
        directory_changed |= self.state.merge_directory(&w.directory);
        self.memory.merge(w.snapshot).await;
        (alive, directory_changed)
    }

    /// Apply another cluster's view of itself (link heartbeat request or
    /// reply).  Returns whether our directory changed.
    fn apply_link_status(&self, cluster: &str, status: &LinkStatus) -> bool {
        let mut changed = self
            .state
            .set_remote_members(cluster, &status.members, &status.retired);
        changed |= self.state.merge_directory(&status.directory);
        self.state.set_remote_sync(cluster, status.sync.clone());
        changed
    }

    /// A sibling in `warning` was heard again: healthy.
    async fn recovered(&self, id: Uuid) {
        let _ = self.nodes.transition(id, NodeTransition::MarkOnline).await;
        let targets: Vec<NodeInfo> = self.state.siblings().into_iter().map(|s| s.info).collect();
        let status = ClusterMessage::PeerStatus {
            node_id: id,
            heartbeat: HeartbeatStatus::Online,
        };
        self.fan_out(&targets, &status).await;
    }

    async fn announce_directory(&self) {
        self.broadcast_siblings(ClusterMessage::Directory(self.state.directory()), false)
            .await;
    }

    async fn announce_alive(&self, clusters: Vec<String>) {
        for cluster in clusters {
            self.broadcast_siblings(ClusterMessage::ClusterAlive { cluster }, false)
                .await;
        }
    }

    /// Contact every seed by address.
    async fn probe_seeds(&self) -> (Delivery, bool) {
        let local = self.state.local();
        let now = self.now();
        let targets: Vec<NodeInfo> = self
            .config
            .seeds
            .iter()
            .filter(|seed| !(seed.host == local.host() && seed.port == local.port))
            .map(|seed| NodeInfo {
                node_id: Uuid::nil(),
                service: String::new(),
                ip: None,
                dns_name: Some(seed.host.clone()),
                port: seed.port,
                version: String::new(),
                started_at: now,
            })
            .collect();
        let probe = ClusterMessage::Probe(local.clone());
        let replies = join_all(targets.iter().map(|t| self.send_to(t, probe.clone()))).await;
        let mut delivery = Delivery::default();
        let mut changed = false;
        let mut alive = Vec::new();
        for reply in replies {
            match reply {
                Ok(Some(ClusterMessage::Welcome(w))) if w.info.node_id != local.node_id => {
                    delivery.sent += 1;
                    let (back, dir) = self.merge_welcome(*w, now).await;
                    alive.extend(back);
                    changed |= dir;
                }
                Ok(_) => delivery.sent += 1,
                Err(_) => delivery.failed += 1,
            }
        }
        self.announce_alive(alive).await;
        (delivery, changed)
    }

    /// One link heartbeat to `cluster`, then repair if our digests differ.
    async fn heartbeat_link(&self, cluster: &str) -> Result<(), AuthError> {
        let status = ClusterMessage::LinkHeartbeat(Box::new(self.link_status().await));
        let reply = self.link_request(cluster, status).await?;
        if let Some(ClusterMessage::LinkHeartbeat(remote)) = reply {
            if remote.info.service == cluster && self.apply_link_status(cluster, &remote) {
                self.announce_directory().await;
            }
            if let (Some(hooks), Some(head)) = (self.hooks(), remote.sync.as_ref()) {
                hooks.on_remote(cluster, head).await;
            }
            if self.state.mark_reachable(cluster) {
                self.announce_alive(vec![cluster.to_string()]).await;
            }
            let key = Uuid::new_v5(&Uuid::NAMESPACE_OID, cluster.as_bytes());
            if remote.digest != self.memory.digest() {
                self.state.want_snapshot(key);
            }
            let cooldown = self.beat() * CLUSTER_SNAPSHOT_COOLDOWN_BEATS as i32;
            if self
                .state
                .snapshots_due(self.now(), cooldown)
                .contains(&key)
                && let Ok(Some(ClusterMessage::Snapshot(snapshot))) = self
                    .link_request(cluster, ClusterMessage::SnapshotRequest)
                    .await
            {
                self.memory.merge(snapshot).await;
            }
        }
        Ok(())
    }

    /// A dead cluster: try each last-known member once, then the seeds.
    async fn reprobe(&self, cluster: &str) {
        self.state.reset_breakers(cluster);
        if self.heartbeat_link(cluster).await.is_ok() {
            return;
        }
        let (_, changed) = self.probe_seeds().await;
        if changed {
            self.announce_directory().await;
        }
    }

    fn report(&self, delivery: Delivery, removed: usize, merged: usize) -> ClusterReport {
        let siblings = self.state.siblings();
        let count = |h| siblings.iter().filter(|s| s.heartbeat == h).count();
        let clusters = self.state.remote_clusters();
        ClusterReport {
            online: count(HeartbeatStatus::Online),
            offline: count(HeartbeatStatus::Offline),
            removed,
            sent: delivery.sent,
            failed: delivery.failed,
            snapshots_merged: merged,
            dead_clusters: clusters.iter().filter(|c| self.state.is_dead(c)).count(),
            clusters: clusters.len(),
            fenced: self.is_fenced(),
        }
    }

    // ── tick steps ──────────────────────────────────────────────────────────

    /// Warnings and evictions.  Returns the number evicted, or `None` if
    /// this instance fenced itself.
    async fn liveness(&self, now: DateTime<Utc>) -> Option<usize> {
        let local = self.state.local_id();
        let beat = self.beat();
        if self
            .state
            .resumed_after_pause(now, beat * self.config.offline_after as i32 + beat / 2)
        {
            return Some(0); // judge the siblings again next round
        }
        let plan = self.state.evaluate_liveness(
            now,
            self.beat(),
            self.config.offline_after,
            self.config.remove_after,
        );
        for id in plan.warnings {
            // Advisory: memory already says warning; a failed write is not
            // retried.
            let _ = self.nodes.transition(id, NodeTransition::MarkOffline).await;
            self.broadcast_siblings(
                ClusterMessage::PeerStatus {
                    node_id: id,
                    heartbeat: HeartbeatStatus::Offline,
                },
                false,
            )
            .await;
        }
        let mut removed = 0;
        for id in plan.evict {
            let address = self.state.sibling(id).map(|s| s.info);
            match self.nodes.evict(id, local).await {
                Ok(EvictOutcome::Evicted | EvictOutcome::AlreadyMissing) => {
                    self.state.retire(id, now);
                    removed += 1;
                    self.broadcast_siblings(ClusterMessage::Evicted { node_id: id }, true)
                        .await;
                    if let Some(address) = address {
                        // Best effort: if it is alive, it fences itself now.
                        let _ = self
                            .send_to(&address, ClusterMessage::Evicted { node_id: id })
                            .await;
                    }
                }
                Ok(EvictOutcome::ObserverMissing) => {
                    self.fence_self();
                    return None;
                }
                Err(_) if !plan.majority => {
                    // Neither the registry nor a majority: we may be the
                    // ones cut off.
                    self.fence_self();
                    return None;
                }
                Err(_) => {} // registry unreachable; try again next tick
            }
        }
        Some(removed)
    }

    async fn sibling_heartbeats(&self) -> Delivery {
        let heartbeat = ClusterMessage::Heartbeat(Heartbeat {
            info: self.state.local(),
            state: self.state.own_state(),
            members: self
                .state
                .siblings()
                .into_iter()
                .filter(|s| s.heartbeat == HeartbeatStatus::Online)
                .map(|s| s.info)
                .collect(),
            digest: self.memory.digest(),
        });
        self.broadcast_siblings(heartbeat, false).await
    }

    async fn retry_outbox(&self) -> Delivery {
        let mut delivery = Delivery::default();
        for mut out in self.state.take_outbox() {
            let Some(sibling) = self.state.sibling(out.to) else {
                continue; // gone: it catches up through join / snapshot
            };
            match self.send_to(&sibling.info, out.payload.clone()).await {
                Ok(_) => delivery.sent += 1,
                Err(_) => {
                    delivery.failed += 1;
                    out.attempts += 1;
                    if out.attempts < CLUSTER_OUTBOX_MAX_ATTEMPTS {
                        self.state.enqueue(out);
                    }
                }
            }
        }
        for mut out in self.state.take_link_outbox() {
            if !self.state.owns_link(&out.cluster) {
                continue; // the new owner repairs through the digest
            }
            match self.link_request(&out.cluster, out.payload.clone()).await {
                Ok(_) => delivery.sent += 1,
                Err(_) => {
                    delivery.failed += 1;
                    out.attempts += 1;
                    if out.attempts < CLUSTER_OUTBOX_MAX_ATTEMPTS {
                        self.state.enqueue_link(out);
                    }
                }
            }
        }
        delivery
    }

    async fn sibling_snapshots(&self, now: DateTime<Utc>) -> usize {
        let cooldown = self.beat() * CLUSTER_SNAPSHOT_COOLDOWN_BEATS as i32;
        let mut merged = 0;
        for peer in self.state.snapshots_due(now, cooldown) {
            let Some(sibling) = self.state.sibling(peer) else {
                continue; // link snapshots are handled with the link heartbeat
            };
            if let Ok(Some(ClusterMessage::Snapshot(snapshot))) = self
                .send_to(&sibling.info, ClusterMessage::SnapshotRequest)
                .await
            {
                self.memory.merge(snapshot).await;
                merged += 1;
            }
        }
        merged
    }

    async fn links(&self, now: DateTime<Utc>) {
        let local = self.state.local_id();
        let cooldown = chrono(self.config.link.breaker_cooldown);
        for cluster in self.state.remote_clusters() {
            if self.is_fenced() {
                return;
            }
            if self.state.is_dead(&cluster) {
                let first = self.state.link_order(&cluster).first().copied();
                if first == Some(local)
                    && self
                        .state
                        .reprobe_due(&cluster, now, chrono(self.config.link.dead_reprobe))
                {
                    self.reprobe(&cluster).await;
                }
                continue;
            }
            let Some(owner) = self.state.link_owner(&cluster) else {
                // Everyone in the current order failed (e.g. the instance
                // that had the link left): treat it as dead, so it is
                // re-probed.
                self.state.mark_dead(&cluster);
                continue;
            };
            if owner != local {
                continue;
            }
            if self.heartbeat_link(&cluster).await.is_err()
                && self.state.link_exhausted(&cluster, self.now(), cooldown)
            {
                let message = match self.state.give_up(&cluster, &[local]) {
                    Handover::Next(tried_by) => ClusterMessage::LinkHandover {
                        cluster: cluster.clone(),
                        tried_by,
                    },
                    Handover::Dead => ClusterMessage::ClusterDead {
                        cluster: cluster.clone(),
                    },
                };
                self.broadcast_siblings(message, true).await;
            }
        }
    }
}

#[async_trait]
impl ClusterService for FederationClusterService {
    fn local(&self) -> NodeInfo {
        self.state.local()
    }

    /// Siblings, then members of other clusters.
    fn peers(&self) -> Vec<PeerState> {
        let now = self.now();
        let siblings = self.state.siblings().into_iter().map(|s| PeerState {
            info: s.info,
            state: s.state,
            heartbeat: s.heartbeat,
            last_heard: s.last_heard,
            known_since: s.known_since,
        });
        let remotes = self
            .state
            .remote_clusters()
            .into_iter()
            .flat_map(|cluster| {
                self.state
                    .remote_members(&cluster)
                    .into_iter()
                    .map(move |m| PeerState {
                        info: m.info,
                        state: m.state,
                        heartbeat: m.heartbeat,
                        last_heard: None,
                        known_since: now,
                    })
            });
        siblings.chain(remotes).collect()
    }

    async fn start(&self) -> Result<ClusterReport, AuthError> {
        let local = self.state.local();
        let now = self.now();
        // Event: an instance is added.
        self.nodes.register(&local).await?;
        if !self.state.has_siblings() {
            for record in self.nodes.list().await? {
                let id = record.info.node_id;
                if id == local.node_id || record.info.service != local.service {
                    continue;
                }
                match (record.heartbeat, record.state) {
                    (HeartbeatStatus::Missing, _) => {
                        self.state.retire(id, record.heartbeat_changed_at);
                    }
                    (_, NodeState::Leaving) => {}
                    (_, state) => {
                        self.state.add_sibling(record.info, state, now);
                    }
                }
            }
        }

        let siblings: Vec<NodeInfo> = self.state.siblings().into_iter().map(|s| s.info).collect();
        let join = ClusterMessage::Join(local.clone());
        let replies = join_all(siblings.iter().map(|to| self.send_to(to, join.clone()))).await;
        let mut delivery = Delivery::default();
        let (mut merged, mut directory_changed) = (0, false);
        let mut alive = Vec::new();
        for reply in replies {
            match reply {
                Ok(Some(ClusterMessage::Welcome(w))) => {
                    delivery.sent += 1;
                    merged += 1;
                    let (back, dir) = self.merge_welcome(*w, now).await;
                    alive.extend(back);
                    directory_changed |= dir;
                }
                Ok(_) => delivery.sent += 1,
                Err(_) => delivery.failed += 1,
            }
        }
        if self.state.remote_clusters().is_empty() {
            let (probed, dir) = self.probe_seeds().await;
            delivery += probed;
            directory_changed |= dir;
        }
        if directory_changed {
            self.announce_directory().await;
        }
        self.announce_alive(alive).await;

        // Event: joining → active.
        self.nodes
            .transition(local.node_id, NodeTransition::Activate)
            .await?;
        self.state.set_own_state(NodeState::Active);
        Ok(self.report(delivery, 0, merged))
    }

    async fn tick(&self) -> Result<ClusterReport, AuthError> {
        if self.is_fenced() {
            return Ok(self.report(Delivery::default(), 0, 0));
        }
        let now = self.now();
        let round = self.ticks.fetch_add(1, Ordering::Relaxed);

        let Some(removed) = self.liveness(now).await else {
            return Ok(self.report(Delivery::default(), 0, 0));
        };
        let mut delivery = self.sibling_heartbeats().await;
        delivery += self.retry_outbox().await;
        let merged = self.sibling_snapshots(now).await;
        self.links(now).await;

        // Isolated from every other cluster: try the seeds again.
        let clusters = self.state.remote_clusters();
        let isolated = clusters.iter().all(|c| self.state.is_dead(c));
        if isolated && round.is_multiple_of(CLUSTER_SEED_PROBE_EVERY) && !self.is_fenced() {
            let (probed, changed) = self.probe_seeds().await;
            delivery += probed;
            if changed {
                self.announce_directory().await;
            }
        }

        let retired_ttl = chrono(self.config.tombstone_ttl);
        self.state
            .prune_seen(now - chrono(self.config.max_skew) * 2);
        self.state.prune_retired(now, retired_ttl);
        if round.is_multiple_of(CLUSTER_SEED_PROBE_EVERY) {
            let _ = self.nodes.purge_retired(self.config.tombstone_ttl).await;
        }
        Ok(self.report(delivery, removed, merged))
    }

    async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        if self.is_fenced() {
            return Err(AuthError::NodeFenced);
        }
        let local = self.state.local();
        let now = self.now();
        if envelope.from == local.node_id {
            return Err(rejected("message from ourselves"));
        }
        if !self.signer.verify(&envelope) {
            return Err(rejected("bad signature"));
        }
        if (now - envelope.sent_at).abs() > chrono(self.config.max_skew) {
            return Err(rejected("timestamp outside the allowed window"));
        }
        let from = envelope.from;
        if self.state.is_retired(from) {
            return self.reply(ClusterMessage::Retired);
        }
        let introduces = matches!(
            envelope.payload,
            ClusterMessage::Join(_)
                | ClusterMessage::Probe(_)
                | ClusterMessage::Heartbeat(_)
                | ClusterMessage::LinkHeartbeat(_)
        );
        if !introduces && !self.state.is_known(from) {
            return Err(rejected("unknown sender"));
        }
        if !self.state.first_sighting(envelope.message_id, now) {
            return Err(rejected("replayed message"));
        }
        let sibling = self.state.is_sibling(from);
        if sibling && self.state.heard_sibling(from, None, None, now) == SiblingHeard::Recovered {
            self.recovered(from).await;
        }
        let require_sibling = || {
            if sibling {
                Ok(())
            } else {
                Err(rejected("intra-cluster message from another cluster"))
            }
        };

        match envelope.payload {
            ClusterMessage::Join(info) => {
                if info.node_id != from || info.service != local.service {
                    return Err(rejected("join from another cluster"));
                }
                self.state
                    .heard_sibling(from, Some(info), Some(NodeState::Joining), now);
                self.reply(self.welcome())
            }
            ClusterMessage::Probe(info) => {
                if info.node_id != from {
                    return Err(rejected("probe for another node"));
                }
                if info.service == local.service {
                    self.state.heard_sibling(from, Some(info), None, now);
                } else {
                    let cluster = info.service.clone();
                    if self.state.add_remote_member(info) {
                        self.announce_directory().await;
                    }
                    if self.state.mark_contacted(&cluster) {
                        self.state.reset_breakers(&cluster);
                        self.announce_alive(vec![cluster]).await;
                    }
                }
                self.reply(self.welcome())
            }
            ClusterMessage::Heartbeat(hb) => {
                if hb.info.node_id != from || hb.info.service != local.service {
                    return Err(rejected("heartbeat from another cluster"));
                }
                // Already marked heard above if it was a known sibling.
                if self
                    .state
                    .heard_sibling(from, Some(hb.info), Some(hb.state), now)
                    == SiblingHeard::Recovered
                {
                    self.recovered(from).await;
                }
                for member in hb.members {
                    self.state.add_sibling(member, NodeState::Active, now);
                }
                if hb.digest != self.memory.digest() {
                    self.state.want_snapshot(from);
                }
                Ok(None)
            }
            ClusterMessage::LinkHeartbeat(status) => {
                let cluster = status.info.service.clone();
                if status.info.node_id != from || cluster == local.service {
                    return Err(rejected("link heartbeat from this cluster"));
                }
                self.state.add_remote_member(status.info.clone());
                if self.apply_link_status(&cluster, &status) {
                    self.announce_directory().await;
                }
                if self.state.mark_contacted(&cluster) {
                    self.state.reset_breakers(&cluster);
                    self.announce_alive(vec![cluster]).await;
                }
                self.reply(ClusterMessage::LinkHeartbeat(Box::new(
                    self.link_status().await,
                )))
            }
            ClusterMessage::NodeUpdated(info) => {
                require_sibling()?;
                if info.node_id == from {
                    self.state.update_sibling_info(info);
                }
                Ok(None)
            }
            ClusterMessage::PeerStatus { node_id, heartbeat } => {
                require_sibling()?;
                match heartbeat {
                    HeartbeatStatus::Missing if node_id == local.node_id => self.fence_self(),
                    HeartbeatStatus::Missing => {
                        self.state.retire(node_id, now);
                    }
                    _ if node_id == local.node_id => {}
                    heartbeat => self.state.set_sibling_heartbeat(node_id, heartbeat),
                }
                Ok(None)
            }
            ClusterMessage::Evicted { node_id } => {
                require_sibling()?;
                if node_id == local.node_id {
                    self.fence_self();
                } else {
                    self.state.retire(node_id, now);
                }
                Ok(None)
            }
            ClusterMessage::Directory(entries) => {
                require_sibling()?;
                self.state.merge_directory(&entries);
                Ok(None)
            }
            ClusterMessage::LinkHandover { cluster, tried_by } => {
                require_sibling()?;
                self.state.give_up(&cluster, &tried_by);
                Ok(None)
            }
            ClusterMessage::ClusterDead { cluster } => {
                require_sibling()?;
                self.state.mark_dead(&cluster);
                Ok(None)
            }
            ClusterMessage::ClusterAlive { cluster } => {
                require_sibling()?;
                if self.state.mark_reachable(&cluster) {
                    self.state.reset_breakers(&cluster);
                }
                Ok(None)
            }
            ClusterMessage::Event(event) => {
                self.memory.apply_event(event.clone()).await;
                if sibling {
                    self.forward_across(&event).await;
                } else {
                    self.broadcast_siblings(ClusterMessage::RelayedEvent(event), true)
                        .await;
                }
                Ok(None)
            }
            ClusterMessage::RelayedEvent(event) => {
                require_sibling()?;
                self.memory.apply_event(event).await;
                Ok(None)
            }
            ClusterMessage::SnapshotRequest => {
                self.reply(ClusterMessage::Snapshot(self.memory.snapshot()))
            }
            ClusterMessage::Snapshot(snapshot) => {
                self.memory.merge(snapshot).await;
                Ok(None)
            }
            ClusterMessage::Leave { node_id } => {
                if node_id == from {
                    if sibling {
                        self.state.forget_sibling(from);
                    } else {
                        self.state.remove_remote_member(from);
                    }
                }
                Ok(None)
            }
            ClusterMessage::Forward { cluster, message } => {
                require_sibling()?;
                let reply = self.link_request(&cluster, *message).await?;
                self.reply(ClusterMessage::ForwardReply(reply.map(Box::new)))
            }
            ClusterMessage::Sync(message) => {
                let Some(hooks) = self.hooks() else {
                    return Err(rejected("federation is not enabled here"));
                };
                match hooks.handle(*message).await? {
                    Some(reply) => self.reply(ClusterMessage::Sync(Box::new(reply))),
                    None => Ok(None),
                }
            }
            ClusterMessage::Welcome(_)
            | ClusterMessage::Retired
            | ClusterMessage::ForwardReply(_) => Err(rejected("reply sent as a request")),
        }
    }

    async fn leave(&self) -> Result<(), AuthError> {
        let local = self.state.local_id();
        // Events: → leaving, tell everyone, then the row goes away.
        self.nodes
            .transition(local, NodeTransition::BeginLeave)
            .await?;
        self.state.set_own_state(NodeState::Leaving);
        let leave = ClusterMessage::Leave { node_id: local };
        self.broadcast_siblings(leave.clone(), false).await;
        for cluster in self.state.remote_clusters() {
            if self.state.owns_link(&cluster) {
                let _ = self.link_request(&cluster, leave.clone()).await;
            }
        }
        self.nodes.transition(local, NodeTransition::Remove).await?;
        Ok(())
    }
}

/// [`EventPublisher`] for federation mode: siblings plus owned links.
/// Holds the cluster weakly — the cluster depends on services that hold
/// this publisher.
#[derive(Default)]
pub(crate) struct FederationPublisher {
    cluster: OnceLock<Weak<FederationClusterService>>,
}

impl FederationPublisher {
    pub fn attach(&self, cluster: &Arc<FederationClusterService>) {
        let _ = self.cluster.set(Arc::downgrade(cluster));
    }
}

#[async_trait]
impl EventPublisher for FederationPublisher {
    async fn publish(&self, event: DomainEvent) {
        if let Some(cluster) = self.cluster.get().and_then(Weak::upgrade) {
            cluster.publish(event).await;
        }
    }
}
