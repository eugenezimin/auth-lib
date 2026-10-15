//! Cluster context — how z-auth instances find each other and push
//! changes (revocations, key events, catalog changes) to one another.
//! Feature `shared`.
//!
//! z-auth ships **no client and no server**.  The host provides:
//! - a [`ClusterTransport`] (outbound: any HTTP / gRPC / bus client), and
//! - an inbound endpoint that hands received envelopes to
//!   [`ClusterService::receive`];
//!
//! plus a [`NodeRepository`] (registry, read at startup).  Token
//! verification never touches the store: every instance keeps the
//! replicated state (denylist, key ring, catalog version) in memory.
//! Protocol: `docs/cluster.md`.

pub mod extension;
pub(crate) mod local;
mod memory;
mod messenger;
pub mod model;
pub mod repository;
pub mod service;
pub mod service_impl;
mod signer;
mod state;
pub mod transport;

pub use extension::SharedCluster;
pub use messenger::ClusterPublisher;
pub use model::{
    ClusterEnvelope, ClusterMessage, ClusterReport, ClusterSnapshot, DirectoryEntry, EvictOutcome,
    Heartbeat, HeartbeatStatus, LinkStatus, MemberStatus, NodeInfo, NodeRecord, NodeState,
    NodeTransition, PeerState, SyncDigest, SyncHead, Welcome,
};
pub use repository::NodeRepository;
pub use service::ClusterService;
pub use service_impl::ClusterServiceImpl;
pub use transport::{ClusterTransport, Delay, NoDelay};

#[cfg(feature = "federation")]
pub(crate) use memory::ReplicatedMemory;
pub(crate) use messenger::ClusterMessenger;
pub(crate) use signer::EnvelopeSigner;
pub(crate) use state::ClusterState;
