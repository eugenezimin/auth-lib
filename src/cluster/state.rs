//! In-memory cluster state: membership and liveness, the retry outbox, the
//! replay guard and snapshot bookkeeping.  No I/O; locks are never held
//! across an `.await`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, RwLock};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::cluster::model::{ClusterMessage, HeartbeatStatus, NodeInfo, NodeState, PeerState};
use crate::constants::CLUSTER_OUTBOX_CAPACITY;

/// A message waiting to be retried.
pub(crate) struct Outgoing {
    pub to: Uuid,
    pub message_id: Uuid,
    pub payload: ClusterMessage,
    pub attempts: u32,
}

/// What hearing from a node meant for membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Heard {
    /// A known, online peer — nothing changed.
    Alive,
    /// A known peer that was offline — now online again.
    BackOnline,
    /// A node we did not know (or had removed) — now online.
    New,
}

/// A liveness change found by [`ClusterState::update_liveness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Liveness {
    /// Missed `offline_after` heartbeats: online → offline.
    WentOffline(Uuid),
    /// Still silent `remove_after` heartbeats later: removed (tombstoned).
    Expired(Uuid),
}

/// A removed peer, remembered for a while and still probed, so it rejoins
/// by itself if it was only cut off.
#[derive(Clone)]
struct Tombstone {
    info: NodeInfo,
    state: NodeState,
    removed_at: DateTime<Utc>,
}

pub(crate) struct ClusterState {
    pub local: NodeInfo,
    /// Our own lifecycle state (reported in heartbeats).
    own_state: RwLock<NodeState>,
    peers: RwLock<HashMap<Uuid, PeerState>>,
    tombstones: RwLock<HashMap<Uuid, Tombstone>>,
    outbox: Mutex<VecDeque<Outgoing>>,
    /// message id → when it was first seen (replay guard)
    seen: Mutex<HashMap<Uuid, DateTime<Utc>>>,
    /// Peers whose digest differed from ours; asked for a snapshot next tick.
    snapshot_wanted: Mutex<HashSet<Uuid>>,
    /// peer → when we last asked it for a snapshot
    snapshot_asked: Mutex<HashMap<Uuid, DateTime<Utc>>>,
}

impl ClusterState {
    pub fn new(local: NodeInfo) -> Self {
        Self {
            local,
            own_state: RwLock::new(NodeState::Joining),
            peers: RwLock::default(),
            tombstones: RwLock::default(),
            outbox: Mutex::default(),
            seen: Mutex::default(),
            snapshot_wanted: Mutex::default(),
            snapshot_asked: Mutex::default(),
        }
    }

    pub fn own_state(&self) -> NodeState {
        *self.own_state.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_own_state(&self, state: NodeState) {
        *self.own_state.write().unwrap_or_else(|e| e.into_inner()) = state;
    }

    // ── membership ──────────────────────────────────────────────────────────

    /// Learn about a node without having heard from it (registry, gossip).
    /// It counts as online until it misses its first heartbeat.
    pub fn discover(&self, info: NodeInfo, state: NodeState, now: DateTime<Utc>) {
        if info.node_id == self.local.node_id {
            return;
        }
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        peers.entry(info.node_id).or_insert(PeerState {
            info,
            state,
            heartbeat: HeartbeatStatus::Online,
            last_heard: None,
            known_since: now,
        });
    }

    /// We heard from a node.  `info` / `state` update what it reports about
    /// itself (heartbeat, join); other messages pass `None`.
    pub fn heard(
        &self,
        from: Uuid,
        info: Option<NodeInfo>,
        state: Option<NodeState>,
        now: DateTime<Utc>,
    ) -> Heard {
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(peer) = peers.get_mut(&from) {
            let was = peer.heartbeat;
            if let Some(info) = info {
                peer.info = info;
            }
            if let Some(state) = state {
                peer.state = state;
            }
            peer.heartbeat = HeartbeatStatus::Online;
            peer.last_heard = Some(now);
            return if was == HeartbeatStatus::Offline {
                Heard::BackOnline
            } else {
                Heard::Alive
            };
        }
        // Unknown or removed: re-add it if we know enough about it.
        let tomb = self
            .tombstones
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&from);
        let Some(info) = info.or_else(|| tomb.as_ref().map(|t| t.info.clone())) else {
            return Heard::Alive; // nothing to identify it by; ignore
        };
        let state = state
            .or_else(|| tomb.map(|t| t.state))
            .unwrap_or(NodeState::Active);
        peers.insert(
            from,
            PeerState {
                info,
                state,
                heartbeat: HeartbeatStatus::Online,
                last_heard: Some(now),
                known_since: now,
            },
        );
        Heard::New
    }

    pub fn is_known(&self, node_id: Uuid) -> bool {
        self.peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&node_id)
            || self
                .tombstones
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&node_id)
    }

    /// A peer left gracefully: forget it entirely (no tombstone).
    pub fn forget(&self, node_id: Uuid) {
        self.peers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node_id);
        self.tombstones
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&node_id);
    }

    pub fn peer(&self, node_id: Uuid) -> Option<PeerState> {
        self.peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node_id)
            .cloned()
    }

    /// Address of a peer, or of a removed peer we still probe.
    pub fn address(&self, node_id: Uuid) -> Option<NodeInfo> {
        self.peer(node_id).map(|p| p.info).or_else(|| {
            self.tombstones
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&node_id)
                .map(|t| t.info.clone())
        })
    }

    /// All peers, sorted by service then node id.
    pub fn peers(&self) -> Vec<PeerState> {
        let mut all: Vec<PeerState> = self
            .peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        all.sort_by(|a, b| {
            (&a.info.service, a.info.node_id).cmp(&(&b.info.service, b.info.node_id))
        });
        all
    }

    /// Removed peers still remembered (probed every few heartbeats).
    pub fn tombstoned(&self) -> Vec<Uuid> {
        self.tombstones
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Re-evaluate liveness.  A heartbeat counts as missed half an interval
    /// after it was due: a peer is offline once silent for
    /// `offline_after + ½` beats, and removed once silent for
    /// `offline_after + remove_after + ½` beats.
    pub fn update_liveness(
        &self,
        now: DateTime<Utc>,
        beat: chrono::Duration,
        offline_after: u32,
        remove_after: u32,
    ) -> Vec<Liveness> {
        let offline_at = beat * offline_after as i32 + beat / 2;
        let remove_at = beat * (offline_after + remove_after) as i32 + beat / 2;
        let mut changes = Vec::new();
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        peers.retain(|id, peer| {
            let silent = now - peer.last_heard.unwrap_or(peer.known_since);
            if silent >= remove_at {
                changes.push(Liveness::Expired(*id));
                self.tombstones
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        *id,
                        Tombstone {
                            info: peer.info.clone(),
                            state: peer.state,
                            removed_at: now,
                        },
                    );
                return false;
            }
            if silent >= offline_at && peer.heartbeat == HeartbeatStatus::Online {
                peer.heartbeat = HeartbeatStatus::Offline;
                changes.push(Liveness::WentOffline(*id));
            }
            true
        });
        changes
    }

    /// Forget tombstones older than `ttl`.
    pub fn prune_tombstones(&self, now: DateTime<Utc>, ttl: chrono::Duration) {
        self.tombstones
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, t| now - t.removed_at < ttl);
    }

    // ── replay guard ────────────────────────────────────────────────────────

    /// `false` if the message id was seen before.
    pub fn first_sighting(&self, message_id: Uuid, now: DateTime<Utc>) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains_key(&message_id) {
            return false;
        }
        seen.insert(message_id, now);
        true
    }

    /// Forget message ids older than `horizon` (they fail the skew check
    /// anyway).
    pub fn prune_seen(&self, horizon: DateTime<Utc>) {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, at| *at >= horizon);
    }

    // ── outbox ──────────────────────────────────────────────────────────────

    pub fn enqueue(&self, outgoing: Outgoing) {
        let mut outbox = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
        if outbox.len() >= CLUSTER_OUTBOX_CAPACITY {
            outbox.pop_front(); // oldest first; anti-entropy repairs it
        }
        outbox.push_back(outgoing);
    }

    pub fn take_outbox(&self) -> Vec<Outgoing> {
        self.outbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect()
    }

    // ── anti-entropy ────────────────────────────────────────────────────────

    pub fn want_snapshot(&self, from: Uuid) {
        self.snapshot_wanted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(from);
    }

    /// Peers to ask for a snapshot now (respecting the per-peer cooldown).
    pub fn snapshots_due(&self, now: DateTime<Utc>, cooldown: chrono::Duration) -> Vec<Uuid> {
        let wanted: Vec<Uuid> = self
            .snapshot_wanted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .collect();
        let mut asked = self
            .snapshot_asked
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        wanted
            .into_iter()
            .filter(|peer| {
                let due = asked.get(peer).is_none_or(|at| now - *at >= cooldown);
                if due {
                    asked.insert(*peer, now);
                }
                due
            })
            .collect()
    }
}
