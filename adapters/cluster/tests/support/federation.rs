//! Federation-mode test world: several clusters (services), each with its
//! own in-memory database and instances, over one in-memory network and
//! one clock.  `ums` is the authority; every other service is a session
//! store.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use z_auth::prelude::*;
use z_auth_cluster::prelude::*;
use uuid::Uuid;

use super::cluster::{CLUSTER_SECRET, Handle, InMemoryNetwork, Node, seed};
use super::{InMemoryDb, MockClock, raw_config, repositories};

pub const BEAT: Duration = Duration::from_secs(2);
pub const AUTHORITY: &str = "ums";

/// One service: its database and its instances.
pub struct Cluster {
    pub name: &'static str,
    pub db: Arc<InMemoryDb>,
    pub nodes: Vec<Arc<Node>>,
}

pub struct World {
    pub network: Arc<InMemoryNetwork>,
    pub clock: Arc<MockClock>,
    pub clusters: Vec<Cluster>,
    pub fenced: Arc<AtomicUsize>,
    /// Shared by every instance (so tokens verify everywhere).
    keys: RawConfig,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    pub fn new() -> Self {
        Self {
            network: InMemoryNetwork::new(),
            clock: MockClock::new(),
            clusters: Vec::new(),
            fenced: Arc::new(AtomicUsize::new(0)),
            keys: raw_config(),
        }
    }

    /// Add (and start) an instance of `service` on `port`.
    pub async fn add(&mut self, service: &'static str, port: u16, seeds: &[u16]) -> Arc<Node> {
        self.add_with(service, port, seeds, |c| c).await
    }

    /// Like [`add`](Self::add), with extra z-auth configuration.
    pub async fn add_with(
        &mut self,
        service: &'static str,
        port: u16,
        seeds: &[u16],
        configure: impl FnOnce(RawConfig) -> RawConfig,
    ) -> Arc<Node> {
        self.add_configured(service, port, seeds, configure, |c| c)
            .await
    }

    /// Like [`add`](Self::add), with extra cluster configuration.
    pub async fn add_with_cluster(
        &mut self,
        service: &'static str,
        port: u16,
        seeds: &[u16],
        cluster: impl FnOnce(RawClusterConfig) -> RawClusterConfig,
    ) -> Arc<Node> {
        self.add_configured(service, port, seeds, |c| c, cluster)
            .await
    }

    async fn add_configured(
        &mut self,
        service: &'static str,
        port: u16,
        seeds: &[u16],
        configure: impl FnOnce(RawConfig) -> RawConfig,
        cluster: impl FnOnce(RawClusterConfig) -> RawClusterConfig,
    ) -> Arc<Node> {
        let idx = match self.clusters.iter().position(|c| c.name == service) {
            Some(i) => i,
            None => {
                self.clusters.push(Cluster {
                    name: service,
                    db: Arc::new(InMemoryDb::new(self.clock.clone())),
                    nodes: Vec::new(),
                });
                self.clusters.len() - 1
            }
        };
        let db = self.clusters[idx].db.clone();
        let seeds: Vec<String> = seeds.iter().map(|p| seed(*p)).collect();
        let fenced = self.fenced.clone();
        let config = configure(self.keys.clone()).build().expect("auth config");
        let settings = cluster(
            RawClusterConfig::default()
                .deployment_mode("federation")
                .authority_service(AUTHORITY)
                .cluster_service(service)
                .cluster_seeds(seeds)
                .cluster_secret(CLUSTER_SECRET)
                .cluster_advertise_ip("127.0.0.1")
                .cluster_advertise_port(port),
        )
        .build()
        .expect("federation config");
        let federation = Arc::new(
            Federation::new(settings, self.network.clone(), db.clone(), db.clone()).on_fenced(
                Arc::new(move || {
                    fenced.fetch_add(1, Ordering::SeqCst);
                }),
            ),
        );
        let builder = if service == AUTHORITY {
            ZAuth::builder(config, repositories(&db)).permissions(db.clone())
        } else {
            let repos = federation.session_store_repositories(SessionRepositories {
                sessions: db.clone(),
                revocations: db.clone(),
                keys: db.clone(),
            });
            ZAuth::builder(config, repos)
        };
        let node = Node::new(
            builder
                .extension(federation.clone())
                .clock(self.clock.clone())
                .build()
                .expect("ZAuth must build"),
            Handle::Federation(federation),
        );
        self.network.attach(&node);
        node.start().await.expect("start");
        self.clusters[idx].nodes.push(node.clone());
        node
    }

    pub fn cluster(&self, name: &str) -> &Cluster {
        self.clusters.iter().find(|c| c.name == name).unwrap()
    }

    /// The first instance of `name`.
    pub fn node(&self, name: &str) -> Arc<Node> {
        self.cluster(name).nodes[0].clone()
    }

    pub fn all(&self) -> Vec<Arc<Node>> {
        self.clusters
            .iter()
            .flat_map(|c| c.nodes.iter().cloned())
            .collect()
    }

    pub fn service_of(&self) -> HashMap<Uuid, &'static str> {
        self.clusters
            .iter()
            .flat_map(|c| c.nodes.iter().map(move |n| (n.node_id(), c.name)))
            .collect()
    }

    /// Advance one heartbeat and tick every instance in `nodes`.
    pub async fn round_of(&self, nodes: &[Arc<Node>]) {
        self.clock.advance(BEAT);
        for n in nodes {
            let _ = n.tick().await;
        }
    }

    pub async fn rounds(&self, n: usize) {
        let all = self.all();
        for _ in 0..n {
            self.round_of(&all).await;
        }
    }
}
