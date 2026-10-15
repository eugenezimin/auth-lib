//! Default [`ClusterService`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::join_all;
use uuid::Uuid;

use crate::config::ClusterConfig;
use crate::constants::{
    CLUSTER_OUTBOX_MAX_ATTEMPTS, CLUSTER_SNAPSHOT_COOLDOWN_BEATS, CLUSTER_TOMBSTONE_PROBE_EVERY,
};
use crate::shared::memory::ReplicatedMemory;
use crate::shared::messenger::ClusterMessenger;
use crate::shared::model::{
    ClusterEnvelope, ClusterMessage, ClusterReport, ClusterSnapshot, Heartbeat, HeartbeatStatus,
    NodeInfo, NodeState, NodeTransition, PeerState, SyncDigest,
};
use crate::shared::repository::NodeRepository;
use crate::shared::service::ClusterService;
use crate::shared::state::{Heard, Liveness, Outgoing};
use z_auth::eventing::DomainEvent;
use z_auth::security::authorization::catalog::CatalogCache;
use z_auth::security::authorization::service::PermissionService;
use z_auth::security::token::denylist::Denylist;
use z_auth::security::token::keyring::KeyRing;
use z_auth::utils::clock::Clock;
use z_auth::utils::error::AuthError;

/// Default [`ClusterService`].
pub struct ClusterServiceImpl {
    messenger: Arc<ClusterMessenger>,
    nodes: Arc<dyn NodeRepository>,
    memory: ReplicatedMemory,
    clock: Arc<dyn Clock>,
    heartbeat: Duration,
    offline_after: u32,
    remove_after: u32,
    tombstone_ttl: Duration,
    ticks: AtomicU64,
    max_skew: Duration,
}

fn rejected(reason: &str) -> AuthError {
    AuthError::ClusterMessageRejected(reason.into())
}

fn chrono(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

impl ClusterServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        messenger: Arc<ClusterMessenger>,
        nodes: Arc<dyn NodeRepository>,
        denylist: Arc<Denylist>,
        keyring: Arc<KeyRing>,
        catalog: Arc<CatalogCache>,
        permissions: Arc<dyn PermissionService>,
        clock: Arc<dyn Clock>,
        config: &ClusterConfig,
    ) -> Self {
        Self {
            messenger,
            nodes,
            memory: ReplicatedMemory {
                denylist,
                keyring,
                catalog,
                permissions,
                clock: clock.clone(),
            },
            clock,
            heartbeat: config.heartbeat,
            offline_after: config.offline_after,
            remove_after: config.remove_after,
            tombstone_ttl: config.tombstone_ttl,
            ticks: AtomicU64::new(0),
            max_skew: config.max_skew,
        }
    }

    fn snapshot(&self) -> ClusterSnapshot {
        self.memory.snapshot()
    }

    fn digest(&self) -> SyncDigest {
        self.memory.digest()
    }

    async fn apply_event(&self, event: DomainEvent) {
        self.memory.apply_event(event).await;
    }

    async fn merge(&self, snapshot: ClusterSnapshot) {
        self.memory.merge(snapshot).await;
    }

    /// Merge a peer's reply if it is a snapshot.
    async fn merge_reply(&self, reply: Option<ClusterEnvelope>) -> bool {
        match reply.map(|r| r.payload) {
            Some(ClusterMessage::Snapshot(snapshot)) => {
                self.merge(snapshot).await;
                true
            }
            _ => false,
        }
    }

    fn reply(&self, payload: ClusterMessage) -> Result<Option<ClusterEnvelope>, AuthError> {
        self.messenger.seal(Uuid::new_v4(), payload).map(Some)
    }

    /// Persist what hearing from `from` meant — only when its state changed.
    async fn on_heard(&self, from: Uuid, heard: Heard) -> Result<(), AuthError> {
        match heard {
            Heard::Alive => Ok(()),
            Heard::BackOnline => self
                .nodes
                .transition(from, NodeTransition::MarkOnline)
                .await
                .map(drop),
            Heard::New => match self.messenger.state.peer(from) {
                Some(peer) => self.nodes.restore(&peer.info, peer.state).await.map(drop),
                None => Ok(()),
            },
        }
    }

    fn report(
        &self,
        sent: usize,
        failed: usize,
        removed: usize,
        snapshots_merged: usize,
    ) -> ClusterReport {
        let peers = self.messenger.state.peers();
        let count = |h| peers.iter().filter(|p| p.heartbeat == h).count();
        ClusterReport {
            online: count(HeartbeatStatus::Online),
            offline: count(HeartbeatStatus::Offline),
            removed,
            sent,
            failed,
            snapshots_merged,
            ..ClusterReport::default()
        }
    }
}

#[async_trait]
impl ClusterService for ClusterServiceImpl {
    fn local(&self) -> NodeInfo {
        self.messenger.state.local.clone()
    }

    fn peers(&self) -> Vec<PeerState> {
        self.messenger.state.peers()
    }

    async fn start(&self) -> Result<ClusterReport, AuthError> {
        let state = &self.messenger.state;
        let now = self.clock.now();
        // Event: a node is added (joining / online).
        self.nodes.register(&state.local).await?;
        for record in self.nodes.list().await? {
            if record.state != NodeState::Leaving {
                state.discover(record.info, record.state, now);
            }
        }

        let join = ClusterMessage::Join(state.local.clone());
        let peers: Vec<Uuid> = state.peers().iter().map(|p| p.info.node_id).collect();
        let replies = join_all(
            peers
                .iter()
                .map(|&to| self.messenger.send(to, Uuid::new_v4(), join.clone())),
        )
        .await;
        let (mut sent, mut failed, mut merged) = (0, 0, 0);
        for (peer, reply) in peers.into_iter().zip(replies) {
            match reply {
                Ok(reply) => {
                    sent += 1;
                    let heard = state.heard(peer, None, None, self.clock.now());
                    self.on_heard(peer, heard).await?;
                    merged += usize::from(self.merge_reply(reply).await);
                }
                Err(_) => failed += 1,
            }
        }

        // Event: joining → active.
        self.nodes
            .transition(state.local.node_id, NodeTransition::Activate)
            .await?;
        state.set_own_state(NodeState::Active);
        Ok(self.report(sent, failed, 0, merged))
    }

    async fn tick(&self) -> Result<ClusterReport, AuthError> {
        let state = &self.messenger.state;
        let now = self.clock.now();
        let beat = chrono(self.heartbeat);
        let round = self.ticks.fetch_add(1, Ordering::Relaxed);

        // 1. Liveness.  Only state changes are written: online → offline,
        //    then offline → removed.  Every observer tries; the guarded
        //    transition lets exactly one of them change the row.
        let mut removed = 0;
        for change in state.update_liveness(now, beat, self.offline_after, self.remove_after) {
            match change {
                Liveness::WentOffline(node) => {
                    self.nodes
                        .transition(node, NodeTransition::MarkOffline)
                        .await?;
                }
                Liveness::Expired(node) => {
                    removed += 1;
                    self.nodes.transition(node, NodeTransition::Expire).await?;
                }
            }
        }
        state.prune_tombstones(now, chrono(self.tombstone_ttl));

        // 2. Heartbeats — to every peer, and every few rounds to removed
        //    peers too, so a node that was only cut off finds its way back.
        let heartbeat = ClusterMessage::Heartbeat(Heartbeat {
            info: state.local.clone(),
            state: state.own_state(),
            members: state
                .peers()
                .into_iter()
                .filter(|p| p.heartbeat == HeartbeatStatus::Online)
                .map(|p| p.info)
                .collect(),
            digest: self.digest(),
        });
        let mut targets: Vec<Uuid> = state.peers().iter().map(|p| p.info.node_id).collect();
        if round.is_multiple_of(CLUSTER_TOMBSTONE_PROBE_EVERY) {
            targets.extend(state.tombstoned());
        }
        let message_id = Uuid::new_v4();
        let results = join_all(
            targets
                .iter()
                .map(|&to| self.messenger.send(to, message_id, heartbeat.clone())),
        )
        .await;
        let mut sent = results.iter().filter(|r| r.is_ok()).count();
        let mut failed = results.len() - sent;

        // 3. Retries (only to current peers).
        for mut out in state.take_outbox() {
            if state.peer(out.to).is_none() {
                continue; // removed: it catches up through join / snapshot
            }
            match self
                .messenger
                .send(out.to, out.message_id, out.payload.clone())
                .await
            {
                Ok(_) => sent += 1,
                Err(_) => {
                    failed += 1;
                    out.attempts += 1;
                    if out.attempts < CLUSTER_OUTBOX_MAX_ATTEMPTS {
                        state.enqueue(Outgoing { ..out });
                    }
                }
            }
        }

        // 4. Anti-entropy: ask peers whose digest differed for a snapshot.
        let mut merged = 0;
        for peer in state.snapshots_due(now, beat * CLUSTER_SNAPSHOT_COOLDOWN_BEATS as i32) {
            if let Ok(reply) = self
                .messenger
                .send(peer, Uuid::new_v4(), ClusterMessage::SnapshotRequest)
                .await
            {
                merged += usize::from(self.merge_reply(reply).await);
            }
        }

        state.prune_seen(now - chrono(self.max_skew) * 2);
        Ok(self.report(sent, failed, removed, merged))
    }

    async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        let state = &self.messenger.state;
        let now = self.clock.now();

        if envelope.from == state.local.node_id {
            return Err(rejected("message from ourselves"));
        }
        if !self.messenger.signer.verify(&envelope) {
            return Err(rejected("bad signature"));
        }
        if (now - envelope.sent_at).abs() > chrono(self.max_skew) {
            return Err(rejected("timestamp outside the allowed window"));
        }
        let introduces_sender = matches!(
            envelope.payload,
            ClusterMessage::Join(_) | ClusterMessage::Heartbeat(_)
        );
        if !introduces_sender && !state.is_known(envelope.from) {
            return Err(rejected("unknown sender"));
        }
        if !state.first_sighting(envelope.message_id, now) {
            return Err(rejected("replayed message"));
        }

        let from = envelope.from;
        match envelope.payload {
            ClusterMessage::Join(info) => {
                if info.node_id != from {
                    return Err(rejected("join for another node"));
                }
                // The joiner registered itself; just remember it.
                state.heard(from, Some(info), Some(NodeState::Joining), now);
                self.reply(ClusterMessage::Snapshot(self.snapshot()))
            }
            ClusterMessage::Leave { node_id } => {
                if node_id == from {
                    state.forget(from);
                }
                Ok(None)
            }
            ClusterMessage::Heartbeat(hb) => {
                if hb.info.node_id != from {
                    return Err(rejected("heartbeat for another node"));
                }
                let heard = state.heard(from, Some(hb.info), Some(hb.state), now);
                self.on_heard(from, heard).await?;
                for member in hb.members {
                    state.discover(member, NodeState::Active, now);
                }
                if hb.digest != self.digest() {
                    state.want_snapshot(from);
                }
                Ok(None)
            }
            ClusterMessage::Event(event) => {
                let heard = state.heard(from, None, None, now);
                self.on_heard(from, heard).await?;
                self.apply_event(event).await;
                Ok(None)
            }
            ClusterMessage::SnapshotRequest => {
                let heard = state.heard(from, None, None, now);
                self.on_heard(from, heard).await?;
                self.reply(ClusterMessage::Snapshot(self.snapshot()))
            }
            ClusterMessage::Snapshot(snapshot) => {
                let heard = state.heard(from, None, None, now);
                self.on_heard(from, heard).await?;
                self.merge(snapshot).await;
                Ok(None)
            }
            _ => Err(rejected("federation-mode message in a shared-mode cluster")),
        }
    }

    async fn leave(&self) -> Result<(), AuthError> {
        let state = &self.messenger.state;
        let local = state.local.node_id;
        // Events: → leaving, tell the peers, then the row goes away.
        self.nodes
            .transition(local, NodeTransition::BeginLeave)
            .await?;
        state.set_own_state(NodeState::Leaving);
        self.messenger
            .broadcast(ClusterMessage::Leave { node_id: local }, false)
            .await;
        self.nodes.transition(local, NodeTransition::Remove).await?;
        Ok(())
    }
}
