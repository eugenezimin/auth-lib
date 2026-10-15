//! [`SharedCluster`] — shared mode as a z-auth [`Extension`]: every
//! instance over one database, pushing revocations, key events and catalog
//! changes to its peers.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use crate::config::{ClusterSettings, DeploymentMode};
use crate::shared::local::local_node;
use crate::shared::{
    ClusterEnvelope, ClusterMessenger, ClusterPublisher, ClusterService, ClusterServiceImpl,
    ClusterState, ClusterTransport, EnvelopeSigner, NodeRepository,
};
use z_auth::controller::extension::{
    AssembleContext, ConfigureContext, Extension, ExtensionReport,
};
use z_auth::utils::error::AuthError;

/// The extension's name in reports.
pub const CLUSTER_EXTENSION: &str = "cluster";

/// Shared mode.  Register it with `ZAuthBuilder::extension` and route the
/// inbound cluster endpoint to [`receive`](Self::receive).
pub struct SharedCluster {
    settings: ClusterSettings,
    transport: Arc<dyn ClusterTransport>,
    nodes: Arc<dyn NodeRepository>,
    messenger: OnceLock<Arc<ClusterMessenger>>,
    service: OnceLock<Arc<dyn ClusterService>>,
}

impl SharedCluster {
    /// `transport` reaches the other instances, `nodes` is the registry
    /// read at startup.  Needs `AUTH_CLUSTER_SECRET`, a port and an address
    /// to advertise.
    pub fn new(
        settings: ClusterSettings,
        transport: Arc<dyn ClusterTransport>,
        nodes: Arc<dyn NodeRepository>,
    ) -> Self {
        Self {
            settings,
            transport,
            nodes,
            messenger: OnceLock::new(),
            service: OnceLock::new(),
        }
    }

    /// The cluster, once `ZAuth` is built.
    pub fn service(&self) -> Option<&Arc<dyn ClusterService>> {
        self.service.get()
    }

    /// Hand an envelope received on the cluster endpoint to the cluster.
    pub async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        self.built()?.receive(envelope).await
    }

    fn built(&self) -> Result<&Arc<dyn ClusterService>, AuthError> {
        self.service
            .get()
            .ok_or_else(|| AuthError::Config("cluster not wired: build ZAuth first".into()))
    }
}

#[async_trait]
impl Extension for SharedCluster {
    fn name(&self) -> &'static str {
        CLUSTER_EXTENSION
    }

    fn configure(&self, ctx: &mut ConfigureContext<'_>) -> Result<(), AuthError> {
        match self.settings.deployment {
            None | Some(DeploymentMode::Shared) => {}
            Some(DeploymentMode::Standalone) => {
                return Err(AuthError::Config(
                    "AUTH_DEPLOYMENT_MODE=standalone, but a cluster transport was configured"
                        .into(),
                ));
            }
            Some(mode) => {
                return Err(AuthError::Config(format!(
                    "AUTH_DEPLOYMENT_MODE={mode}, but the shared-mode cluster was configured"
                )));
            }
        }
        let messenger = Arc::new(ClusterMessenger::new(
            Arc::new(ClusterState::new(local_node(
                &self.settings,
                ctx.node_id(),
                ctx.clock(),
            )?)),
            EnvelopeSigner::new(self.settings.cluster.secret.clone().ok_or_else(|| {
                AuthError::Config("missing AUTH_CLUSTER_SECRET (cluster configured)".into())
            })?),
            self.transport.clone(),
            ctx.clock().clone(),
        ));
        self.messenger
            .set(messenger.clone())
            .map_err(|_| AuthError::Config("extension already attached".into()))?;
        ctx.subscribe(Arc::new(ClusterPublisher::new(messenger)));
        Ok(())
    }

    fn assemble(&self, ctx: &mut AssembleContext<'_>) -> Result<(), AuthError> {
        let messenger = self.messenger.get().expect("configured first").clone();
        let core = ctx.core();
        let service: Arc<dyn ClusterService> = Arc::new(ClusterServiceImpl::new(
            messenger,
            self.nodes.clone(),
            core.denylist().clone(),
            core.keyring().clone(),
            core.catalog().clone(),
            ctx.permissions().clone(),
            core.clock().clone(),
            &self.settings.cluster,
        ));
        let _ = self.service.set(service);
        Ok(())
    }

    async fn start(&self) -> Result<Option<ExtensionReport>, AuthError> {
        let report = self.built()?.start().await?;
        Ok(Some(ExtensionReport::new(CLUSTER_EXTENSION, report)))
    }

    async fn tick(&self) -> Result<Option<ExtensionReport>, AuthError> {
        let report = self.built()?.tick().await?;
        Ok(Some(ExtensionReport::new(CLUSTER_EXTENSION, report)))
    }

    async fn shutdown(&self) -> Result<(), AuthError> {
        self.built()?.leave().await
    }
}
