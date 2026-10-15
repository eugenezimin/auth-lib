//! In-memory state of a federation-mode instance: its cluster's members
//! (siblings), retired ids, the directory of other clusters and the links
//! to them, plus the outboxes and the replay guard.  No I/O; the lock is
//! never held across an `.await`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::constants::CLUSTER_OUTBOX_CAPACITY;
use crate::federation::membership::breaker::Breaker;
use crate::shared::model::{
    ClusterMessage, DirectoryEntry, HeartbeatStatus, MemberStatus, NodeInfo, NodeState, SyncHead,
};
use z_auth::utils::fence::ServingFence;

/// Another instance of this instance's own cluster.
#[derive(Debug, Clone)]
pub(crate) struct Sibling {
    pub info: NodeInfo,
    pub state: NodeState,
    /// `Online` = healthy, `Offline` = warning.
    pub heartbeat: HeartbeatStatus,
    pub last_heard: Option<DateTime<Utc>>,
    pub known_since: DateTime<Utc>,
}

/// What hearing from a sibling meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SiblingHeard {
    Alive,
    /// It was in `warning`; now healthy again.
    Recovered,
    New,
    /// Not a sibling and nothing to identify it by.
    Unknown,
}

/// Link from this cluster to another one, as seen by this instance.
#[derive(Debug, Default)]
pub(crate) struct Link {
    breakers: HashMap<Uuid, Breaker>,
    /// Siblings that gave up on this cluster in the current failure round.
    tried_by: BTreeSet<Uuid>,
    dead: bool,
    last_probe: Option<DateTime<Utc>>,
    /// Last target that answered — tried first next time.
    target: Option<Uuid>,
    sync: Option<SyncHead>,
}

#[derive(Debug, Default)]
struct Remote {
    members: BTreeMap<Uuid, MemberStatus>,
    link: Link,
}

/// An intra-cluster message waiting to be retried.
pub(crate) struct Outgoing {
    pub to: Uuid,
    pub payload: ClusterMessage,
    pub attempts: u32,
}

/// A message for another cluster waiting to be retried.
pub(crate) struct LinkOutgoing {
    pub cluster: String,
    pub payload: ClusterMessage,
    pub attempts: u32,
}

/// What the liveness round decided.
#[derive(Debug, Default)]
pub(crate) struct LivenessPlan {
    /// Siblings that just went healthy → warning.
    pub warnings: Vec<Uuid>,
    /// Siblings to evict now.
    pub evict: Vec<Uuid>,
    /// This instance reaches a majority of its cluster (counting itself).
    pub majority: bool,
}

/// Result of a link owner giving up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Handover {
    /// Another sibling is next; tell everyone who tried.
    Next(Vec<Uuid>),
    /// Every sibling tried: the cluster is dead.
    Dead,
}

struct Inner {
    local: NodeInfo,
    own_state: NodeState,
    /// When this instance last ran its liveness round.
    last_round: Option<DateTime<Utc>>,
    siblings: HashMap<Uuid, Sibling>,
    retired: HashMap<Uuid, DateTime<Utc>>,
    remotes: BTreeMap<String, Remote>,
    seen: HashMap<Uuid, DateTime<Utc>>,
    outbox: VecDeque<Outgoing>,
    link_outbox: VecDeque<LinkOutgoing>,
    snapshot_wanted: HashSet<Uuid>,
    snapshot_asked: HashMap<Uuid, DateTime<Utc>>,
}

pub(crate) struct MeshState {
    inner: Mutex<Inner>,
    /// Shared with the token verifier and the fenced service wrappers.
    fenced: ServingFence,
}

/// Rendezvous rank of `node` for `cluster`: who owns the link to it.
fn rank(node: Uuid, cluster: &str) -> u64 {
    let mut hash = Sha256::new();
    hash.update(node.as_bytes());
    hash.update(cluster.as_bytes());
    let digest = hash.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// Random permutation (link targets are picked at random).
fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let mut buf = [0u8; 8];
        let j = match getrandom::fill(&mut buf) {
            Ok(()) => (u64::from_le_bytes(buf) % (i as u64 + 1)) as usize,
            Err(_) => i, // no randomness: keep the order
        };
        items.swap(i, j);
    }
}

impl MeshState {
    pub fn new(local: NodeInfo, fenced: ServingFence) -> Self {
        Self {
            inner: Mutex::new(Inner {
                local,
                own_state: NodeState::Joining,
                last_round: None,
                siblings: HashMap::new(),
                retired: HashMap::new(),
                remotes: BTreeMap::new(),
                seen: HashMap::new(),
                outbox: VecDeque::new(),
                link_outbox: VecDeque::new(),
                snapshot_wanted: HashSet::new(),
                snapshot_asked: HashMap::new(),
            }),
            fenced,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── self ────────────────────────────────────────────────────────────────

    pub fn local(&self) -> NodeInfo {
        self.lock().local.clone()
    }

    pub fn local_id(&self) -> Uuid {
        self.lock().local.node_id
    }

    pub fn set_local(&self, info: NodeInfo) {
        self.lock().local = info;
    }

    pub fn own_state(&self) -> NodeState {
        self.lock().own_state
    }

    pub fn set_own_state(&self, state: NodeState) {
        self.lock().own_state = state;
    }

    /// `true` the first time.
    pub fn fence(&self) -> bool {
        self.fenced.fence()
    }

    pub fn is_fenced(&self) -> bool {
        self.fenced.is_fenced()
    }

    // ── siblings ────────────────────────────────────────────────────────────

    /// Learn about a sibling without having heard from it (registry,
    /// gossip).  Ignores ourselves, retired ids and other clusters.
    pub fn add_sibling(&self, info: NodeInfo, state: NodeState, now: DateTime<Utc>) -> bool {
        let mut s = self.lock();
        if info.node_id == s.local.node_id
            || info.service != s.local.service
            || s.retired.contains_key(&info.node_id)
            || s.siblings.contains_key(&info.node_id)
        {
            return false;
        }
        s.siblings.insert(
            info.node_id,
            Sibling {
                info,
                state,
                heartbeat: HeartbeatStatus::Online,
                last_heard: None,
                known_since: now,
            },
        );
        true
    }

    /// We heard from `from`.  `info` / `state` update what it says about
    /// itself (join, heartbeat).
    pub fn heard_sibling(
        &self,
        from: Uuid,
        info: Option<NodeInfo>,
        state: Option<NodeState>,
        now: DateTime<Utc>,
    ) -> SiblingHeard {
        let mut s = self.lock();
        if s.retired.contains_key(&from) {
            return SiblingHeard::Unknown;
        }
        if let Some(sib) = s.siblings.get_mut(&from) {
            let was = sib.heartbeat;
            if let Some(info) = info {
                sib.info = info;
            }
            if let Some(state) = state {
                sib.state = state;
            }
            sib.heartbeat = HeartbeatStatus::Online;
            sib.last_heard = Some(now);
            return if was == HeartbeatStatus::Offline {
                SiblingHeard::Recovered
            } else {
                SiblingHeard::Alive
            };
        }
        let Some(info) = info.filter(|i| i.service == s.local.service) else {
            return SiblingHeard::Unknown;
        };
        s.siblings.insert(
            from,
            Sibling {
                info,
                state: state.unwrap_or(NodeState::Active),
                heartbeat: HeartbeatStatus::Online,
                last_heard: Some(now),
                known_since: now,
            },
        );
        SiblingHeard::New
    }

    pub fn is_sibling(&self, id: Uuid) -> bool {
        self.lock().siblings.contains_key(&id)
    }

    pub fn sibling(&self, id: Uuid) -> Option<Sibling> {
        self.lock().siblings.get(&id).cloned()
    }

    /// Sorted by node id.
    pub fn siblings(&self) -> Vec<Sibling> {
        let mut all: Vec<Sibling> = self.lock().siblings.values().cloned().collect();
        all.sort_by_key(|s| s.info.node_id);
        all
    }

    pub fn has_siblings(&self) -> bool {
        !self.lock().siblings.is_empty()
    }

    pub fn forget_sibling(&self, id: Uuid) {
        self.lock().siblings.remove(&id);
    }

    /// Another sibling's observation (`PeerStatus`).
    pub fn set_sibling_heartbeat(&self, id: Uuid, heartbeat: HeartbeatStatus) {
        if let Some(sib) = self.lock().siblings.get_mut(&id) {
            sib.heartbeat = heartbeat;
        }
    }

    pub fn update_sibling_info(&self, info: NodeInfo) -> bool {
        match self.lock().siblings.get_mut(&info.node_id) {
            Some(sib) if sib.info != info => {
                sib.info = info;
                true
            }
            _ => false,
        }
    }

    /// This cluster as members see it (this instance included).
    pub fn members(&self) -> Vec<MemberStatus> {
        let s = self.lock();
        let mut members: Vec<MemberStatus> = std::iter::once(MemberStatus {
            info: s.local.clone(),
            state: s.own_state,
            heartbeat: HeartbeatStatus::Online,
        })
        .chain(s.siblings.values().map(|sib| MemberStatus {
            info: sib.info.clone(),
            state: sib.state,
            heartbeat: sib.heartbeat,
        }))
        .collect();
        members.sort_by_key(|m| m.info.node_id);
        members
    }

    /// Whether this instance was itself suspended (process paused, tick
    /// loop stalled) for longer than `limit` since its last round.  Its
    /// view of the siblings is then stale: they are given a fresh start
    /// instead of being judged on our own silence.
    pub fn resumed_after_pause(&self, now: DateTime<Utc>, limit: chrono::Duration) -> bool {
        let mut s = self.lock();
        let paused = s.last_round.is_some_and(|at| now - at > limit);
        s.last_round = Some(now);
        if paused {
            for sib in s.siblings.values_mut() {
                sib.last_heard = Some(now);
            }
        }
        paused
    }

    /// Re-evaluate the siblings' liveness and decide evictions.
    ///
    /// A heartbeat counts as missed half an interval after it was due: a
    /// sibling goes to `warning` once silent for `warning_after + ½`
    /// beats, and is evictable once silent for `warning_after +
    /// missing_after + ½` beats.  Evictions go first to the side holding a
    /// majority (ties: the side with the lowest node id); the other side
    /// waits `missing_after` more beats, which gives the majority time to
    /// evict it first through the registry.
    pub fn evaluate_liveness(
        &self,
        now: DateTime<Utc>,
        beat: chrono::Duration,
        warning_after: u32,
        missing_after: u32,
    ) -> LivenessPlan {
        let warn_at = beat * warning_after as i32 + beat / 2;
        let miss_at = beat * (warning_after + missing_after) as i32 + beat / 2;
        let grace = beat * missing_after as i32;
        let mut s = self.lock();
        let local = s.local.node_id;
        let mut plan = LivenessPlan::default();

        let mut reachable = vec![local];
        let mut silent_for: Vec<(Uuid, chrono::Duration)> = Vec::new();
        for (id, sib) in s.siblings.iter_mut() {
            let silent = now - sib.last_heard.unwrap_or(sib.known_since);
            if silent >= warn_at && sib.heartbeat == HeartbeatStatus::Online {
                sib.heartbeat = HeartbeatStatus::Offline;
                plan.warnings.push(*id);
            }
            if silent < miss_at {
                reachable.push(*id);
            } else {
                silent_for.push((*id, silent));
            }
        }
        let size = s.siblings.len() + 1;
        let lowest_overall = s.siblings.keys().copied().chain([local]).min();
        let lowest_reachable = reachable.iter().copied().min();
        plan.majority = 2 * reachable.len() > size;
        let priority =
            plan.majority || (2 * reachable.len() == size && lowest_reachable == lowest_overall);
        plan.evict = silent_for
            .into_iter()
            .filter(|(_, silent)| priority || *silent >= miss_at + grace)
            .map(|(id, _)| id)
            .collect();
        plan.evict.sort();
        plan.warnings.sort();
        plan
    }

    // ── retired ids ─────────────────────────────────────────────────────────

    /// Retire `id`: it is no longer a sibling and its messages are refused.
    pub fn retire(&self, id: Uuid, at: DateTime<Utc>) -> bool {
        let mut s = self.lock();
        if id == s.local.node_id {
            return false;
        }
        s.siblings.remove(&id);
        for remote in s.remotes.values_mut() {
            remote.members.remove(&id);
        }
        s.retired.insert(id, at).is_none()
    }

    pub fn is_retired(&self, id: Uuid) -> bool {
        self.lock().retired.contains_key(&id)
    }

    pub fn retired(&self) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = self.lock().retired.keys().copied().collect();
        ids.sort();
        ids
    }

    pub fn prune_retired(&self, now: DateTime<Utc>, ttl: chrono::Duration) {
        self.lock().retired.retain(|_, at| now - *at < ttl);
    }

    // ── other clusters ──────────────────────────────────────────────────────

    /// Cluster of a known remote member.
    pub fn remote_cluster_of(&self, id: Uuid) -> Option<String> {
        let s = self.lock();
        s.remotes
            .iter()
            .find(|(_, r)| r.members.contains_key(&id))
            .map(|(name, _)| name.clone())
    }

    pub fn is_known(&self, id: Uuid) -> bool {
        self.is_sibling(id) || self.remote_cluster_of(id).is_some()
    }

    pub fn remote_clusters(&self) -> Vec<String> {
        self.lock().remotes.keys().cloned().collect()
    }

    pub fn remote_members(&self, cluster: &str) -> Vec<MemberStatus> {
        self.lock()
            .remotes
            .get(cluster)
            .map(|r| r.members.values().cloned().collect())
            .unwrap_or_default()
    }

    /// A node of another cluster contacted us (probe, link heartbeat).
    pub fn add_remote_member(&self, info: NodeInfo) -> bool {
        let mut s = self.lock();
        if info.service == s.local.service {
            return false;
        }
        let remote = s.remotes.entry(info.service.clone()).or_default();
        match remote.members.get_mut(&info.node_id) {
            Some(m) if m.info == info => false,
            Some(m) => {
                m.info = info;
                true
            }
            None => {
                remote.members.insert(
                    info.node_id,
                    MemberStatus {
                        info,
                        state: NodeState::Active,
                        heartbeat: HeartbeatStatus::Online,
                    },
                );
                true
            }
        }
    }

    /// A cluster told us its own membership: it is authoritative.
    pub fn set_remote_members(
        &self,
        cluster: &str,
        members: &[MemberStatus],
        retired: &[Uuid],
    ) -> bool {
        let mut s = self.lock();
        if cluster == s.local.service {
            return false;
        }
        let remote = s.remotes.entry(cluster.to_string()).or_default();
        let next: BTreeMap<Uuid, MemberStatus> = members
            .iter()
            .filter(|m| {
                m.info.service == cluster
                    && m.heartbeat != HeartbeatStatus::Missing
                    && !retired.contains(&m.info.node_id)
            })
            .map(|m| (m.info.node_id, m.clone()))
            .collect();
        let changed = next != remote.members;
        remote.link.breakers.retain(|id, _| next.contains_key(id));
        remote.members = next;
        changed
    }

    /// Learn clusters (and members of them) from someone's directory.
    /// Existing members are left alone: a cluster's own word wins.
    pub fn merge_directory(&self, entries: &[DirectoryEntry]) -> bool {
        let mut s = self.lock();
        let local_service = s.local.service.clone();
        let mut changed = false;
        for entry in entries {
            if entry.cluster == local_service {
                continue;
            }
            let remote = s.remotes.entry(entry.cluster.clone()).or_insert_with(|| {
                changed = true;
                Remote::default()
            });
            for info in entry.members.iter().filter(|i| i.service == entry.cluster) {
                if let std::collections::btree_map::Entry::Vacant(slot) =
                    remote.members.entry(info.node_id)
                {
                    slot.insert(MemberStatus {
                        info: info.clone(),
                        state: NodeState::Active,
                        heartbeat: HeartbeatStatus::Online,
                    });
                    changed = true;
                }
            }
        }
        changed
    }

    pub fn remove_remote_member(&self, id: Uuid) {
        for remote in self.lock().remotes.values_mut() {
            remote.members.remove(&id);
            remote.link.breakers.remove(&id);
        }
    }

    /// Other clusters and their last-known members.
    pub fn directory(&self) -> Vec<DirectoryEntry> {
        self.lock()
            .remotes
            .iter()
            .map(|(cluster, r)| DirectoryEntry {
                cluster: cluster.clone(),
                members: r.members.values().map(|m| m.info.clone()).collect(),
            })
            .collect()
    }

    // ── links ───────────────────────────────────────────────────────────────

    /// Healthy instances of this cluster (this one included), ordered by
    /// rendezvous rank for `cluster`: the first one owns the link.
    pub fn link_order(&self, cluster: &str) -> Vec<Uuid> {
        let s = self.lock();
        let mut ids: Vec<Uuid> = s
            .siblings
            .values()
            .filter(|sib| sib.heartbeat == HeartbeatStatus::Online)
            .map(|sib| sib.info.node_id)
            .chain([s.local.node_id])
            .collect();
        ids.sort_by(|a, b| rank(*b, cluster).cmp(&rank(*a, cluster)).then(a.cmp(b)));
        ids
    }

    /// Current owner of the link to `cluster`: the first in rendezvous
    /// order that has not given up.  `None` while the cluster is dead.
    pub fn link_owner(&self, cluster: &str) -> Option<Uuid> {
        let order = self.link_order(cluster);
        let s = self.lock();
        let link = &s.remotes.get(cluster)?.link;
        if link.dead {
            return None;
        }
        order.into_iter().find(|id| !link.tried_by.contains(id))
    }

    pub fn owns_link(&self, cluster: &str) -> bool {
        self.link_owner(cluster) == Some(self.local_id())
    }

    pub fn is_dead(&self, cluster: &str) -> bool {
        self.lock()
            .remotes
            .get(cluster)
            .is_some_and(|r| r.link.dead)
    }

    /// Targets to try for `cluster`: members not evicted whose breaker
    /// allows a request — the last target that answered first, then the
    /// rest in random order.
    pub fn link_targets(
        &self,
        cluster: &str,
        now: DateTime<Utc>,
        cooldown: chrono::Duration,
    ) -> Vec<NodeInfo> {
        let s = self.lock();
        let Some(remote) = s.remotes.get(cluster) else {
            return Vec::new();
        };
        let allowed = |id: &Uuid| {
            remote
                .link
                .breakers
                .get(id)
                .is_none_or(|b| b.allows(now, cooldown))
        };
        let mut rest: Vec<NodeInfo> = remote
            .members
            .values()
            .filter(|m| m.heartbeat != HeartbeatStatus::Missing && allowed(&m.info.node_id))
            .filter(|m| Some(m.info.node_id) != remote.link.target)
            .map(|m| m.info.clone())
            .collect();
        shuffle(&mut rest);
        let first = remote
            .link
            .target
            .filter(allowed)
            .and_then(|id| remote.members.get(&id))
            .filter(|m| m.heartbeat != HeartbeatStatus::Missing)
            .map(|m| m.info.clone());
        first.into_iter().chain(rest).collect()
    }

    pub fn link_success(&self, cluster: &str, target: Uuid) {
        if let Some(remote) = self.lock().remotes.get_mut(cluster) {
            remote.link.breakers.entry(target).or_default().success();
            remote.link.target = Some(target);
        }
    }

    pub fn link_failure(&self, cluster: &str, target: Uuid, now: DateTime<Utc>, threshold: u32) {
        if let Some(remote) = self.lock().remotes.get_mut(cluster) {
            remote
                .link
                .breakers
                .entry(target)
                .or_default()
                .failure(now, threshold);
            if remote.link.target == Some(target) {
                remote.link.target = None;
            }
        }
    }

    /// Every known target of `cluster` has an open breaker (or there is
    /// none to try).
    pub fn link_exhausted(
        &self,
        cluster: &str,
        now: DateTime<Utc>,
        cooldown: chrono::Duration,
    ) -> bool {
        let s = self.lock();
        let Some(remote) = s.remotes.get(cluster) else {
            return true;
        };
        remote
            .members
            .values()
            .filter(|m| m.heartbeat != HeartbeatStatus::Missing)
            .all(|m| {
                remote
                    .link
                    .breakers
                    .get(&m.info.node_id)
                    .is_some_and(|b| b.is_open(now, cooldown))
            })
    }

    /// This instance gives up on `cluster`, or a sibling told us it did.
    pub fn give_up(&self, cluster: &str, tried_by: &[Uuid]) -> Handover {
        let order = self.link_order(cluster);
        let mut s = self.lock();
        let remote = s.remotes.entry(cluster.to_string()).or_default();
        remote.link.tried_by.extend(tried_by.iter().copied());
        if order.iter().all(|id| remote.link.tried_by.contains(id)) {
            remote.link.dead = true;
            remote.link.tried_by.clear();
            Handover::Dead
        } else {
            Handover::Next(remote.link.tried_by.iter().copied().collect())
        }
    }

    /// Returns `true` if the cluster was not already dead.
    pub fn mark_dead(&self, cluster: &str) -> bool {
        let mut s = self.lock();
        let remote = s.remotes.entry(cluster.to_string()).or_default();
        remote.link.tried_by.clear();
        !std::mem::replace(&mut remote.link.dead, true)
    }

    /// We (or a sibling, via `ClusterAlive`) reached a cluster that was
    /// marked dead: it is alive and the failure round starts over.  While
    /// it is not dead, a success changes nothing — the link stays with the
    /// instance that works, and those that failed stay out of the order.
    /// Returns `true` if it was dead.
    pub fn mark_reachable(&self, cluster: &str) -> bool {
        let mut s = self.lock();
        let Some(remote) = s.remotes.get_mut(cluster) else {
            return false;
        };
        if !remote.link.dead {
            return false;
        }
        remote.link.dead = false;
        remote.link.tried_by.clear();
        true
    }

    /// `cluster` contacted us.  It is not dead, but that says nothing
    /// about whether our link owner reaches it, so a handover in progress
    /// stays as it is.  Returns `true` if it was dead.
    pub fn mark_contacted(&self, cluster: &str) -> bool {
        let mut s = self.lock();
        let Some(remote) = s.remotes.get_mut(cluster) else {
            return false;
        };
        std::mem::replace(&mut remote.link.dead, false)
    }

    /// Whether a dead cluster should be probed now (records the probe).
    pub fn reprobe_due(&self, cluster: &str, now: DateTime<Utc>, every: chrono::Duration) -> bool {
        let mut s = self.lock();
        let Some(remote) = s.remotes.get_mut(cluster) else {
            return false;
        };
        let due = remote.link.last_probe.is_none_or(|at| now - at >= every);
        if due {
            remote.link.last_probe = Some(now);
        }
        due
    }

    /// Reset the breakers of a cluster that came back.
    pub fn reset_breakers(&self, cluster: &str) {
        if let Some(remote) = self.lock().remotes.get_mut(cluster) {
            remote.link.breakers.clear();
        }
    }

    pub fn set_remote_sync(&self, cluster: &str, sync: Option<SyncHead>) {
        if let Some(remote) = self.lock().remotes.get_mut(cluster) {
            remote.link.sync = sync;
        }
    }

    #[allow(dead_code)] // read by the sync engine
    pub fn remote_sync(&self, cluster: &str) -> Option<SyncHead> {
        self.lock()
            .remotes
            .get(cluster)
            .and_then(|r| r.link.sync.clone())
    }

    // ── replay guard ────────────────────────────────────────────────────────

    pub fn first_sighting(&self, message_id: Uuid, now: DateTime<Utc>) -> bool {
        let mut s = self.lock();
        if s.seen.contains_key(&message_id) {
            return false;
        }
        s.seen.insert(message_id, now);
        true
    }

    pub fn prune_seen(&self, horizon: DateTime<Utc>) {
        self.lock().seen.retain(|_, at| *at >= horizon);
    }

    // ── outboxes ────────────────────────────────────────────────────────────

    pub fn enqueue(&self, outgoing: Outgoing) {
        let mut s = self.lock();
        if s.outbox.len() >= CLUSTER_OUTBOX_CAPACITY {
            s.outbox.pop_front();
        }
        s.outbox.push_back(outgoing);
    }

    pub fn take_outbox(&self) -> Vec<Outgoing> {
        self.lock().outbox.drain(..).collect()
    }

    pub fn enqueue_link(&self, outgoing: LinkOutgoing) {
        let mut s = self.lock();
        if s.link_outbox.len() >= CLUSTER_OUTBOX_CAPACITY {
            s.link_outbox.pop_front();
        }
        s.link_outbox.push_back(outgoing);
    }

    pub fn take_link_outbox(&self) -> Vec<LinkOutgoing> {
        self.lock().link_outbox.drain(..).collect()
    }

    // ── anti-entropy ────────────────────────────────────────────────────────

    pub fn want_snapshot(&self, from: Uuid) {
        self.lock().snapshot_wanted.insert(from);
    }

    pub fn snapshots_due(&self, now: DateTime<Utc>, cooldown: chrono::Duration) -> Vec<Uuid> {
        let mut s = self.lock();
        let wanted: Vec<Uuid> = s.snapshot_wanted.drain().collect();
        wanted
            .into_iter()
            .filter(|peer| {
                let due = s
                    .snapshot_asked
                    .get(peer)
                    .is_none_or(|at| now - *at >= cooldown);
                if due {
                    s.snapshot_asked.insert(*peer, now);
                }
                due
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(service: &str) -> NodeInfo {
        NodeInfo {
            node_id: Uuid::new_v4(),
            service: service.into(),
            ip: Some("127.0.0.1".parse().unwrap()),
            dns_name: None,
            port: 1,
            version: "t".into(),
            started_at: Utc::now(),
        }
    }

    fn beat() -> chrono::Duration {
        chrono::Duration::seconds(2)
    }

    impl MeshState {
        fn of(local: NodeInfo) -> Self {
            Self::new(local, ServingFence::new())
        }
    }

    #[test]
    fn warning_then_eviction_with_majority() {
        let t0 = Utc::now();
        let state = MeshState::of(node("a"));
        let (b, c) = (node("a"), node("a"));
        state.add_sibling(b.clone(), NodeState::Active, t0);
        state.add_sibling(c.clone(), NodeState::Active, t0);

        // c keeps talking, b goes silent.
        let at = |secs| t0 + chrono::Duration::seconds(secs);
        state.heard_sibling(c.node_id, None, None, at(3));
        let plan = state.evaluate_liveness(at(3), beat(), 1, 1);
        assert_eq!(plan.warnings, vec![b.node_id], "missed one beat (+½)");
        assert!(plan.evict.is_empty());

        state.heard_sibling(c.node_id, None, None, at(5));
        let plan = state.evaluate_liveness(at(5), beat(), 1, 1);
        assert!(plan.majority);
        assert_eq!(plan.evict, vec![b.node_id], "missed one more beat");
    }

    #[test]
    fn minority_waits_for_the_majority() {
        let t0 = Utc::now();
        let state = MeshState::of(node("a"));
        let others: Vec<NodeInfo> = (0..2).map(|_| node("a")).collect();
        for o in &others {
            state.add_sibling(o.clone(), NodeState::Active, t0);
        }
        let at = |secs| t0 + chrono::Duration::seconds(secs);
        // Alone against two silent siblings: no majority.
        let plan = state.evaluate_liveness(at(5), beat(), 1, 1);
        assert!(!plan.majority);
        assert!(plan.evict.is_empty(), "the majority gets the first try");
        let plan = state.evaluate_liveness(at(7), beat(), 1, 1);
        assert_eq!(plan.evict.len(), 2, "after one more beat it may try");
    }

    #[test]
    fn tie_goes_to_the_side_with_the_lowest_id() {
        let t0 = Utc::now();
        let at = |secs| t0 + chrono::Duration::seconds(secs);
        let (x, y) = (node("a"), node("a"));
        let (low, high) = if x.node_id < y.node_id {
            (x, y)
        } else {
            (y, x)
        };

        let state = MeshState::of(low.clone());
        state.add_sibling(high.clone(), NodeState::Active, t0);
        assert_eq!(
            state.evaluate_liveness(at(5), beat(), 1, 1).evict,
            vec![high.node_id]
        );

        let state = MeshState::of(high);
        state.add_sibling(low, NodeState::Active, t0);
        assert!(
            state
                .evaluate_liveness(at(5), beat(), 1, 1)
                .evict
                .is_empty()
        );
    }

    #[test]
    fn link_ownership_and_handover() {
        let state = MeshState::of(node("a"));
        let t0 = Utc::now();
        let sibs: Vec<NodeInfo> = (0..2).map(|_| node("a")).collect();
        for s in &sibs {
            state.add_sibling(s.clone(), NodeState::Active, t0);
        }
        state.add_remote_member(node("b"));
        let order = state.link_order("b");
        assert_eq!(order.len(), 3);
        assert_eq!(state.link_owner("b"), Some(order[0]));

        assert_eq!(
            state.give_up("b", &[order[0]]),
            Handover::Next(vec![order[0]])
        );
        assert_eq!(state.link_owner("b"), Some(order[1]));
        assert!(matches!(state.give_up("b", &[order[1]]), Handover::Next(_)));
        assert_eq!(state.give_up("b", &[order[2]]), Handover::Dead);
        assert!(state.is_dead("b"));
        assert_eq!(state.link_owner("b"), None);
        assert!(state.mark_reachable("b"));
        assert_eq!(state.link_owner("b"), Some(order[0]), "a new round");

        // A success while not dead keeps the link where it works.
        state.give_up("b", &[order[0]]);
        assert!(!state.mark_reachable("b"));
        assert_eq!(state.link_owner("b"), Some(order[1]));
    }

    #[test]
    fn retired_ids_are_dropped_everywhere() {
        let t0 = Utc::now();
        let state = MeshState::of(node("a"));
        let b = node("a");
        state.add_sibling(b.clone(), NodeState::Active, t0);
        assert!(state.retire(b.node_id, t0));
        assert!(!state.is_sibling(b.node_id));
        assert!(
            !state.add_sibling(b.clone(), NodeState::Active, t0),
            "stays retired"
        );
        assert_eq!(
            state.heard_sibling(b.node_id, Some(b), None, t0),
            SiblingHeard::Unknown
        );
    }
}
