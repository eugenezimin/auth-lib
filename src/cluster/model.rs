//! Cluster models and the wire DTOs exchanged between auth-lib instances.
//!
//! [`ClusterEnvelope`] is the only thing that crosses the wire: the host's
//! transport serializes it (JSON via serde, or any format) and its
//! controller hands it back to
//! [`ClusterService::receive`](crate::cluster::ClusterService::receive).

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::events::DomainEvent;
use crate::token::model::{Revocation, VerifyingKeyRecord};

/// Identity and address of one auth-lib instance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    /// Generated per process start.
    pub node_id: Uuid,
    /// Service the instance belongs to (e.g. `auth`, `orders`).
    pub service: String,
    pub ip: Option<IpAddr>,
    pub dns_name: Option<String>,
    pub port: u16,
    /// auth-lib version.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatStatus {
    Online,
    Offline,
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
    pub online: usize,
    pub offline: usize,
    /// Peers removed (expired) this round.
    pub removed: usize,
    /// Messages delivered / failed this round.
    pub sent: usize,
    pub failed: usize,
    pub snapshots_merged: usize,
}
