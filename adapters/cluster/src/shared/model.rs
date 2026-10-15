//! Cluster models and the wire DTOs exchanged between z-auth instances.
//!
//! [`ClusterEnvelope`] is the only thing that crosses the wire: the host's
//! transport serializes it (JSON via serde, or any format) and its
//! controller hands it back to
//! [`ClusterService::receive`](crate::shared::ClusterService::receive).

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use z_auth::eventing::DomainEvent;
use z_auth::security::token::model::{Revocation, VerifyingKeyRecord};

/// Identity and address of one z-auth instance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    /// Generated per process start.
    pub node_id: Uuid,
    /// Service the instance belongs to (e.g. `auth`, `orders`).
    pub service: String,
    pub ip: Option<IpAddr>,
    pub dns_name: Option<String>,
    pub port: u16,
    /// z-auth version.
    pub version: String,
    pub started_at: DateTime<Utc>,
}

impl NodeInfo {
    /// Host to connect to: the DNS name if advertised, else the IP.
    pub fn host(&self) -> String {
        match (&self.dns_name, self.ip) {
            (Some(dns), _) => dns.clone(),
            (None, Some(ip)) => ip.to_string(),
            (None, None) => String::new(),
        }
    }
}

/// Lifecycle state of a node — the registry's state machine.
///
/// ```text
///   (start) ──► joining ──activate──► active ──begin_leave──► leaving ──remove──► (deleted)
///                  └───────────────begin_leave─────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// Registered; announcing itself to the cluster.
    Joining,
    /// Joined and serving.
    Active,
    /// Shutting down gracefully.
    Leaving,
}

/// Heartbeat status of a node, as last observed by its peers.
///
/// ```text
///   online ──missed `offline_after` beats──► offline ──missed `remove_after` more──► (deleted)
///     ▲                                        │
///     └──────────── heartbeat heard ───────────┘
/// ```
///
/// Federation mode reads `online` as *healthy* and `offline` as *warning*,
/// and replaces deletion with `missing`: the node was evicted by its own
/// cluster, its id is retired and its messages are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatStatus {
    Online,
    Offline,
    /// Federation mode only: evicted, id retired.
    Missing,
}

/// Outcome of [`NodeRepository::evict`](crate::shared::NodeRepository::evict).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictOutcome {
    /// This call marked the node missing.
    Evicted,
    /// Another observer already did.
    AlreadyMissing,
    /// The observer itself is marked missing — it lost the race and must
    /// fence itself.
    ObserverMissing,
}

/// A registry change.  Every transition is guarded by the state it starts
/// from, so a repository applies it as a conditional, idempotent write:
/// when several instances observe the same event, exactly one changes the
/// row and the others change nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeTransition {
    /// `joining → active` — the node finished announcing itself.
    Activate,
    /// `joining | active → leaving` — graceful shutdown begins.
    BeginLeave,
    /// `leaving → (deleted)` — graceful shutdown finished.
    Remove,
    /// heartbeat `online → offline` — a heartbeat was missed.
    MarkOffline,
    /// heartbeat `offline → online` — heard from it again.
    MarkOnline,
    /// heartbeat `offline → (deleted)` — still silent.
    Expire,
}

/// A node as stored in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub info: NodeInfo,
    pub state: NodeState,
    pub heartbeat: HeartbeatStatus,
    pub state_changed_at: DateTime<Utc>,
    pub heartbeat_changed_at: DateTime<Utc>,
}

/// A peer as this instance sees it (in memory).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerState {
    pub info: NodeInfo,
    /// Lifecycle state the peer last reported.
    pub state: NodeState,
    pub heartbeat: HeartbeatStatus,
    /// Last message received from it.
    pub last_heard: Option<DateTime<Utc>>,
    /// When this instance learned about it.
    pub known_since: DateTime<Utc>,
}

// ── Wire DTOs ─────────────────────────────────────────────────────────────────

/// A signed cluster message.  `mac` = base64url(HMAC-SHA256(cluster secret,
/// JSON of every other field)); see `docs/cluster.md`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClusterEnvelope {
    pub message_id: Uuid,
    /// Sending node.
    pub from: Uuid,
    pub sent_at: DateTime<Utc>,
    pub payload: ClusterMessage,
    pub mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClusterMessage {
    /// A node started; the reply is a [`ClusterSnapshot`].
    Join(NodeInfo),
    /// A node shuts down gracefully.
    Leave {
        node_id: Uuid,
    },
    Heartbeat(Heartbeat),
    /// Something changed — push.
    Event(DomainEvent),
    /// Ask for the sender's state; the reply is a [`ClusterSnapshot`].
    SnapshotRequest,
    Snapshot(ClusterSnapshot),

    // ── federation mode only ────────────────────────────────────────────
    /// Contact by address (seeds): the reply is a [`Welcome`].
    Probe(NodeInfo),
    /// Reply to `Join` / `Probe`.
    Welcome(Box<Welcome>),
    /// A sibling's advertised address changed.
    NodeUpdated(NodeInfo),
    /// A sibling's liveness as observed by another sibling.
    PeerStatus {
        node_id: Uuid,
        heartbeat: HeartbeatStatus,
    },
    /// The cluster evicted `node_id`; its id is retired.
    Evicted {
        node_id: Uuid,
    },
    /// Reply to any message from a retired node id.
    Retired,
    /// Other clusters' members, shared between siblings.
    Directory(Vec<DirectoryEntry>),
    /// Link heartbeat between clusters; the reply is one too.
    LinkHeartbeat(Box<LinkStatus>),
    /// This link owner gave up on `cluster`; the next sibling takes over.
    LinkHandover {
        cluster: String,
        tried_by: Vec<Uuid>,
    },
    /// Every sibling failed to reach `cluster`.
    ClusterDead {
        cluster: String,
    },
    /// `cluster` is reachable again.
    ClusterAlive {
        cluster: String,
    },
    /// An event that arrived from another cluster, fanned out to siblings.
    /// Never forwarded again.
    RelayedEvent(DomainEvent),
    /// Ask the link owner for `cluster` to deliver `message` there; the
    /// reply is a `ForwardReply` with the remote reply's payload.
    Forward {
        cluster: String,
        message: Box<ClusterMessage>,
    },
    ForwardReply(Option<Box<ClusterMessage>>),
    /// Federation sync between clusters: feed pulls, session fetches.
    #[cfg(feature = "federation")]
    Sync(Box<crate::sync::SyncMessage>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Heartbeat {
    pub info: NodeInfo,
    /// The sender's lifecycle state.
    pub state: NodeState,
    /// Peers the sender sees online — lets members discover each other.
    pub members: Vec<NodeInfo>,
    /// Summary of the sender's state; a mismatch triggers a snapshot request.
    pub digest: SyncDigest,
}

/// Order-independent fingerprints of the replicated state.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncDigest {
    pub revocations: String,
    pub keys: String,
    pub catalog_version: u64,
}

/// The replicated state, for joining nodes and anti-entropy repair.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ClusterSnapshot {
    pub revocations: Vec<Revocation>,
    pub keys: Vec<VerifyingKeyRecord>,
    pub catalog_version: u64,
}

/// Outcome of `start` / `tick`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClusterReport {
    /// Shared mode: online peers.  Federation mode: healthy instances of
    /// this cluster.
    pub online: usize,
    /// Shared mode: offline peers.  Federation mode: instances of this
    /// cluster in `warning`.
    pub offline: usize,
    /// Peers removed (expired, or evicted in federation mode) this round.
    pub removed: usize,
    /// Messages delivered / failed this round.
    pub sent: usize,
    pub failed: usize,
    pub snapshots_merged: usize,
    /// Federation mode: other clusters known / currently unreachable.
    pub clusters: usize,
    pub dead_clusters: usize,
    /// Federation mode: this instance is fenced and must be restarted.
    pub fenced: bool,
}

// ── Federation-mode wire DTOs ─────────────────────────────────────────────────

/// A node and how its own cluster sees it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberStatus {
    pub info: NodeInfo,
    pub state: NodeState,
    pub heartbeat: HeartbeatStatus,
}

/// Last-known members of another cluster.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryEntry {
    pub cluster: String,
    pub members: Vec<NodeInfo>,
}

/// Sync progress advertised by a cluster (federation mode).  Opaque
/// to membership; compared by the sync engine.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncHead {
    /// The cluster database's identity.
    pub site_id: Uuid,
    /// Feed head: `(txid, seq)`.
    pub head: (u64, u64),
    pub protocol: u16,
    /// Hash of the settings every cluster must agree on.
    pub config_fingerprint: String,
}

/// Reply to `Join` and `Probe` in federation mode: everything a newcomer
/// needs to find its way around.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Welcome {
    /// The responder.
    pub info: NodeInfo,
    /// The responder's cluster, the responder included.
    pub members: Vec<MemberStatus>,
    /// Node ids the responder's cluster evicted.
    pub retired: Vec<Uuid>,
    /// Other clusters the responder knows.
    pub directory: Vec<DirectoryEntry>,
    pub snapshot: ClusterSnapshot,
}

/// Exchanged on the link between two clusters, every heartbeat (request
/// and reply carry the sender's side).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkStatus {
    pub info: NodeInfo,
    /// The sender's cluster, the sender included.
    pub members: Vec<MemberStatus>,
    pub retired: Vec<Uuid>,
    pub directory: Vec<DirectoryEntry>,
    pub digest: SyncDigest,
    pub sync: Option<SyncHead>,
}
