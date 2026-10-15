//! In-memory cluster transport for tests: routes envelopes between
//! in-process instances ([`Node`]s), can partition nodes, and records traffic.

use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use uuid::Uuid;
use z_auth::prelude::*;
#[cfg(feature = "federation")]
use z_auth_cluster::federation::FederationEngine;
use z_auth_cluster::prelude::*;

use crate::support::{InMemoryDb, MockClock, raw_config};

/// base64 of 32 bytes of 0x2a.
pub const CLUSTER_SECRET: &str = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";

/// The cluster extension a [`Node`] was built with.
pub enum Handle {
    Shared(Arc<SharedCluster>),
    #[cfg(feature = "federation")]
    Federation(Arc<Federation>),
}

/// One instance: its `ZAuth` plus the cluster handle the host keeps.
pub struct Node {
    pub auth: ZAuth,
    pub handle: Handle,
}

impl Deref for Node {
    type Target = ZAuth;
    fn deref(&self) -> &ZAuth {
        &self.auth
    }
}

impl Node {
    pub fn new(auth: ZAuth, handle: Handle) -> Arc<Self> {
        Arc::new(Self { auth, handle })
    }

    /// The cluster (either mode).
    pub fn cluster(&self) -> Option<&dyn ClusterService> {
        match &self.handle {
            Handle::Shared(c) => c.service().map(|s| s.as_ref()),
            #[cfg(feature = "federation")]
            Handle::Federation(f) => f.cluster().map(|c| c.as_ref() as &dyn ClusterService),
        }
    }

    /// Federation mode: the sync engine.
    #[cfg(feature = "federation")]
    pub fn federation(&self) -> Option<&Arc<FederationEngine>> {
        match &self.handle {
            Handle::Federation(f) => f.engine(),
            _ => None,
        }
    }

    /// Federation mode: the cluster with its inter-cluster links.
    #[cfg(feature = "federation")]
    pub fn federation_cluster(&self) -> Option<&Arc<FederationClusterService>> {
        match &self.handle {
            Handle::Federation(f) => f.cluster(),
            _ => None,
        }
    }

    pub async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        match &self.handle {
            Handle::Shared(c) => c.receive(envelope).await,
            #[cfg(feature = "federation")]
            Handle::Federation(f) => f.receive(envelope).await,
        }
    }
}

#[derive(Default)]
pub struct InMemoryNetwork {
    nodes: Mutex<HashMap<Uuid, Weak<Node>>>,
    /// `host:port` → node, for seed probes (nil node id).
    addresses: Mutex<HashMap<String, Uuid>>,
    cut: Mutex<HashSet<Uuid>>,
    /// Links that fail in both directions.
    cut_pairs: Mutex<HashSet<(Uuid, Uuid)>>,
    log: Mutex<Vec<(Uuid, ClusterEnvelope)>>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn attach(&self, auth: &Arc<Node>) {
        self.nodes
            .lock()
            .unwrap()
            .insert(auth.node_id(), Arc::downgrade(auth));
        if let Some(cluster) = auth.cluster() {
            let local = cluster.local();
            self.addresses
                .lock()
                .unwrap()
                .insert(format!("{}:{}", local.host(), local.port), auth.node_id());
        }
    }

    /// Stop routing to `node` (a crashed process).
    pub fn detach(&self, node: Uuid) {
        self.nodes.lock().unwrap().remove(&node);
        self.addresses.lock().unwrap().retain(|_, id| *id != node);
    }

    /// Messages between `a` and `b` fail (both directions) until
    /// [`heal_pair`](Self::heal_pair).
    pub fn partition_pair(&self, a: Uuid, b: Uuid) {
        let mut cut = self.cut_pairs.lock().unwrap();
        cut.insert((a, b));
        cut.insert((b, a));
    }

    pub fn heal_pair(&self, a: Uuid, b: Uuid) {
        let mut cut = self.cut_pairs.lock().unwrap();
        cut.remove(&(a, b));
        cut.remove(&(b, a));
    }

    /// Cut every link between the two groups.
    pub fn partition_groups(&self, left: &[Uuid], right: &[Uuid]) {
        for a in left {
            for b in right {
                self.partition_pair(*a, *b);
            }
        }
    }

    pub fn heal_all(&self) {
        self.cut.lock().unwrap().clear();
        self.cut_pairs.lock().unwrap().clear();
    }

    pub fn clear_log(&self) {
        self.log.lock().unwrap().clear();
    }

    /// Messages to and from `node` fail until [`heal`](Self::heal).
    pub fn partition(&self, node: Uuid) {
        self.cut.lock().unwrap().insert(node);
    }

    pub fn heal(&self, node: Uuid) {
        self.cut.lock().unwrap().remove(&node);
    }

    /// Every delivered envelope with its target, oldest first.
    pub fn log(&self) -> Vec<(Uuid, ClusterEnvelope)> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl ClusterTransport for InMemoryNetwork {
    async fn send(
        &self,
        to: &NodeInfo,
        envelope: &ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        let unreachable = || AuthError::ClusterUnreachable(to.node_id.to_string());
        let target_id = if to.node_id.is_nil() {
            *self
                .addresses
                .lock()
                .unwrap()
                .get(&format!("{}:{}", to.host(), to.port))
                .ok_or_else(unreachable)?
        } else {
            to.node_id
        };
        {
            let cut = self.cut.lock().unwrap();
            if cut.contains(&target_id) || cut.contains(&envelope.from) {
                return Err(unreachable());
            }
            if self
                .cut_pairs
                .lock()
                .unwrap()
                .contains(&(envelope.from, target_id))
            {
                return Err(unreachable());
            }
        }
        let target = self
            .nodes
            .lock()
            .unwrap()
            .get(&target_id)
            .and_then(Weak::upgrade)
            .ok_or_else(unreachable)?;
        self.log.lock().unwrap().push((target_id, envelope.clone()));
        target.receive(envelope.clone()).await
    }
}

/// A cluster member over a shared store, clock and network.  `port` only
/// has to be unique.
pub fn cluster_node(
    network: &Arc<InMemoryNetwork>,
    db: &Arc<InMemoryDb>,
    clock: &Arc<MockClock>,
    config: RawConfig,
    port: u16,
) -> Arc<Node> {
    let config = config.build().expect("auth config");
    let settings = RawClusterConfig::default()
        .cluster_secret(CLUSTER_SECRET)
        .cluster_advertise_ip("127.0.0.1")
        .cluster_advertise_port(port)
        .build()
        .expect("cluster config");
    let cluster = Arc::new(SharedCluster::new(settings, network.clone(), db.clone()));
    let auth = Node::new(
        ZAuth::builder(config, super::repositories(db))
            .permissions(db.clone())
            .extension(cluster.clone())
            .clock(clock.clone())
            .build()
            .expect("ZAuth must build"),
        Handle::Shared(cluster),
    );
    network.attach(&auth);
    auth
}

/// `n` started members, each with its own signing key.
pub async fn started_cluster(
    n: usize,
) -> (
    Arc<InMemoryNetwork>,
    Arc<InMemoryDb>,
    Arc<MockClock>,
    Vec<Arc<Node>>,
) {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let network = InMemoryNetwork::new();
    let mut nodes = Vec::new();
    for i in 0..n {
        let node = cluster_node(&network, &db, &clock, raw_config(), 9000 + i as u16);
        node.start().await.expect("start");
        nodes.push(node);
    }
    (network, db, clock, nodes)
}

pub fn seed(port: u16) -> String {
    format!("127.0.0.1:{port}")
}
