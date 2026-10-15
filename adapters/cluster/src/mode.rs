//! [`Cluster`] — pick the cluster mode from the configuration
//! (`AUTH_DEPLOYMENT_MODE`) instead of in code.

use std::sync::Arc;

use crate::config::{ClusterSettings, DeploymentMode};
#[cfg(feature = "federation")]
use crate::federation::{Federation, SyncStore, membership::FenceHook};
use crate::shared::{ClusterEnvelope, ClusterTransport, Delay, NodeRepository, SharedCluster};
use z_auth::controller::extension::Extension;
use z_auth::utils::error::AuthError;

/// What the host supplies to either mode.
pub struct ClusterAdapters {
    /// Reaches the other instances.
    pub transport: Arc<dyn ClusterTransport>,
    /// The node registry (federation mode: this service's own instances).
    pub nodes: Arc<dyn NodeRepository>,
    /// Federation mode (required): this cluster's change feed, snapshots
    /// and cursors.
    #[cfg(feature = "federation")]
    pub sync_store: Option<Arc<dyn SyncStore>>,
    /// Federation mode: waits between retries of inter-cluster requests.
    pub delay: Option<Arc<dyn Delay>>,
    /// Federation mode: called once when this instance fences itself.
    #[cfg(feature = "federation")]
    pub on_fenced: Option<FenceHook>,
}

/// The cluster in the configured mode.
pub enum Cluster {
    Shared(Arc<SharedCluster>),
    #[cfg(feature = "federation")]
    Federation(Arc<Federation>),
}

impl Cluster {
    /// `AUTH_DEPLOYMENT_MODE` unset or `shared` → [`SharedCluster`],
    /// `federation` → [`Federation`] (needs `sync_store`), `standalone` →
    /// an error: run without a cluster instead.
    pub fn new(settings: ClusterSettings, adapters: ClusterAdapters) -> Result<Self, AuthError> {
        match settings.deployment {
            None | Some(DeploymentMode::Shared) => Ok(Self::Shared(Arc::new(SharedCluster::new(
                settings,
                adapters.transport,
                adapters.nodes,
            )))),
            Some(DeploymentMode::Standalone) => Err(AuthError::Config(
                "AUTH_DEPLOYMENT_MODE=standalone, but a cluster transport was configured".into(),
            )),
            #[cfg(feature = "federation")]
            Some(DeploymentMode::Federation) => {
                let store = adapters.sync_store.ok_or_else(|| {
                    AuthError::Config(
                        "federation mode: missing adapter: sync_store (ClusterAdapters)".into(),
                    )
                })?;
                let mut federation =
                    Federation::new(settings, adapters.transport, adapters.nodes, store);
                if let Some(delay) = adapters.delay {
                    federation = federation.delay(delay);
                }
                if let Some(hook) = adapters.on_fenced {
                    federation = federation.on_fenced(hook);
                }
                Ok(Self::Federation(Arc::new(federation)))
            }
            #[cfg(not(feature = "federation"))]
            Some(DeploymentMode::Federation) => Err(AuthError::Config(
                "AUTH_DEPLOYMENT_MODE=federation needs the `federation` feature".into(),
            )),
        }
    }

    /// The resolved mode.
    pub fn mode(&self) -> DeploymentMode {
        match self {
            Self::Shared(_) => DeploymentMode::Shared,
            #[cfg(feature = "federation")]
            Self::Federation(_) => DeploymentMode::Federation,
        }
    }

    /// Register with `ZAuthBuilder::extension`.
    pub fn extension(&self) -> Arc<dyn Extension> {
        match self {
            Self::Shared(c) => c.clone(),
            #[cfg(feature = "federation")]
            Self::Federation(f) => f.clone(),
        }
    }

    /// Hand an envelope received on the cluster endpoint to the cluster.
    pub async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        match self {
            Self::Shared(c) => c.receive(envelope).await,
            #[cfg(feature = "federation")]
            Self::Federation(f) => f.receive(envelope).await,
        }
    }
}
