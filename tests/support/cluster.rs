//! In-memory cluster transport for tests: routes envelopes between
//! in-process [`AuthLib`] instances, can partition nodes, and records traffic.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use auth_lib::prelude::*;
use uuid::Uuid;

use crate::support::{InMemoryDb, MockClock, raw_config};

/// base64 of 32 bytes of 0x2a.
pub const CLUSTER_SECRET: &str = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";

#[derive(Default)]
pub struct InMemoryNetwork {
    nodes: Mutex<HashMap<Uuid, Weak<AuthLib>>>,
    cut: Mutex<HashSet<Uuid>>,
    log: Mutex<Vec<(Uuid, ClusterEnvelope)>>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn attach(&self, auth: &Arc<AuthLib>) {
        self.nodes
            .lock()
            .unwrap()
            .insert(auth.node_id(), Arc::downgrade(auth));
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
        {
            let cut = self.cut.lock().unwrap();
            if cut.contains(&to.node_id) || cut.contains(&envelope.from) {
                return Err(unreachable());
            }
        }
        let target = self
            .nodes
            .lock()
            .unwrap()
            .get(&to.node_id)
            .and_then(Weak::upgrade)
            .ok_or_else(unreachable)?;
        self.log
            .lock()
            .unwrap()
            .push((to.node_id, envelope.clone()));
        target
            .cluster()
            .expect("cluster node")
            .receive(envelope.clone())
            .await
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
) -> Arc<AuthLib> {
    let config = config
        .cluster_secret(CLUSTER_SECRET)
        .cluster_advertise_ip("127.0.0.1")
        .cluster_advertise_port(port)
        .build()
        .expect("cluster config");
    let auth = Arc::new(
        AuthLib::builder(config, super::repositories(db))
            .permissions(db.clone())
            .cluster(network.clone(), db.clone())
            .clock(clock.clone())
            .build()
            .expect("AuthLib must build"),
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
    Vec<Arc<AuthLib>>,
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
