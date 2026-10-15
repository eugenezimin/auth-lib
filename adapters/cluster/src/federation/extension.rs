//! [`Federation`] — federation mode as a z-auth [`Extension`]: database
//! per service, the authority owns identity, every other service keeps a
//! session store, and session state is synced between them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;

use crate::config::{ClusterSettings, DeploymentMode, SelfFence};
use crate::federation::guard::{
    Authority, NoRoleStore, NoUserRoleStore, NoUserStore, NotAuthorityLogin, NotAuthorityRoles,
    NotAuthorityUsers, SnapshotAccountSource, SnapshotPermissions,
};
use crate::federation::membership::{
    FederationClusterService, FederationPublisher, FenceHook, MeshState, SyncHooks,
};
use crate::federation::producer::{
    ProducingLogin, ProducingPermissions, ProducingRoles, ProducingUsers, SnapshotProducer,
};
use crate::federation::{FederationEngine, SyncStore};
use crate::fence::{FencedAuthentication, FencedRevocation};
use crate::shared::extension::CLUSTER_EXTENSION;
use crate::shared::local::local_node;
use crate::shared::{
    ClusterEnvelope, ClusterService, ClusterTransport, Delay, EnvelopeSigner, NoDelay,
    NodeRepository, ReplicatedMemory,
};
use z_auth::controller::extension::{
    AssembleContext, ConfigureContext, DecorateContext, Extension, ExtensionReport,
};
use z_auth::controller::facade::Repositories;
use z_auth::security::session::SessionRepository;
use z_auth::security::token::{KeyRepository, RevocationRepository};
use z_auth::utils::error::AuthError;
use z_auth::utils::fence::ServingFence;

/// The storage of a session store (every service except the authority):
/// no users, roles or grants.
pub struct SessionRepositories {
    pub sessions: Arc<dyn SessionRepository>,
    pub revocations: Arc<dyn RevocationRepository>,
    pub keys: Arc<dyn KeyRepository>,
}

/// Federation mode.  Register it with `ZAuthBuilder::extension` and route
/// the inbound cluster endpoint to [`receive`](Self::receive).
pub struct Federation {
    settings: ClusterSettings,
    transport: Arc<dyn ClusterTransport>,
    nodes: Arc<dyn NodeRepository>,
    store: Arc<dyn SyncStore>,
    delay: Option<Arc<dyn Delay>>,
    on_fenced: Mutex<Option<FenceHook>>,
    authority: Authority,
    is_authority: bool,
    /// [`session_store_repositories`](Self::session_store_repositories) was used.
    session_store: AtomicBool,
    publisher: Arc<FederationPublisher>,
    fence: OnceLock<ServingFence>,
    cluster: OnceLock<Arc<FederationClusterService>>,
    engine: OnceLock<Arc<FederationEngine>>,
    producer: OnceLock<Arc<SnapshotProducer>>,
}

impl Federation {
    /// `transport` reaches every instance (this cluster's and the other
    /// clusters'), `nodes` is the registry of this service's own instances
    /// and `store` this cluster's change feed, snapshots and cursors — both
    /// in this service's database.
    pub fn new(
        settings: ClusterSettings,
        transport: Arc<dyn ClusterTransport>,
        nodes: Arc<dyn NodeRepository>,
        store: Arc<dyn SyncStore>,
    ) -> Self {
        let authority = settings
            .federation
            .authority_service
            .clone()
            .unwrap_or_default();
        Self {
            is_authority: authority == settings.cluster.service,
            settings,
            transport,
            nodes,
            store,
            delay: None,
            on_fenced: Mutex::new(None),
            authority: Authority::new(authority),
            session_store: AtomicBool::new(false),
            publisher: Arc::new(FederationPublisher::default()),
            fence: OnceLock::new(),
            cluster: OnceLock::new(),
            engine: OnceLock::new(),
            producer: OnceLock::new(),
        }
    }

    /// Waits between retries of inter-cluster requests (e.g.
    /// `tokio::time::sleep`).  Defaults to [`NoDelay`].
    pub fn delay(mut self, delay: Arc<dyn Delay>) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Called once when this instance fences itself.  The host should
    /// restart the process.
    pub fn on_fenced(self, hook: FenceHook) -> Self {
        *self.on_fenced.lock().unwrap_or_else(|e| e.into_inner()) = Some(hook);
        self
    }

    /// Every service except the authority: the [`Repositories`] of a session
    /// store.  Users, roles and grants belong to the authority, so their
    /// repositories answer [`AuthError::NotAuthority`].
    pub fn session_store_repositories(&self, repos: SessionRepositories) -> Repositories {
        self.session_store.store(true, Ordering::SeqCst);
        Repositories {
            users: Arc::new(NoUserStore(self.authority.clone())),
            roles: Arc::new(NoRoleStore(self.authority.clone())),
            user_roles: Arc::new(NoUserRoleStore(self.authority.clone())),
            sessions: repos.sessions,
            revocations: repos.revocations,
            keys: repos.keys,
        }
    }

    /// This service is the authority (`AUTH_AUTHORITY_SERVICE`).
    pub fn is_authority(&self) -> bool {
        self.is_authority
    }

    /// The cluster with its inter-cluster links, once `ZAuth` is built.
    pub fn cluster(&self) -> Option<&Arc<FederationClusterService>> {
        self.cluster.get()
    }

    /// The sync engine (reports, refresh gate), once `ZAuth` is built.
    pub fn engine(&self) -> Option<&Arc<FederationEngine>> {
        self.engine.get()
    }

    /// This instance was evicted or lost its quorum and refuses to serve.
    pub fn is_fenced(&self) -> bool {
        self.fence.get().is_some_and(ServingFence::is_fenced)
    }

    /// Hand an envelope received on the cluster endpoint to the cluster.
    pub async fn receive(
        &self,
        envelope: ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        self.built()?.receive(envelope).await
    }

    fn built(&self) -> Result<&Arc<FederationClusterService>, AuthError> {
        self.cluster
            .get()
            .ok_or_else(|| AuthError::Config("cluster not wired: build ZAuth first".into()))
    }

    fn engine_built(&self) -> Result<&Arc<FederationEngine>, AuthError> {
        self.engine
            .get()
            .ok_or_else(|| AuthError::Config("cluster not wired: build ZAuth first".into()))
    }
}

#[async_trait]
impl Extension for Federation {
    fn name(&self) -> &'static str {
        CLUSTER_EXTENSION
    }

    fn configure(&self, ctx: &mut ConfigureContext<'_>) -> Result<(), AuthError> {
        match self.settings.deployment {
            None | Some(DeploymentMode::Federation) => {}
            Some(mode) => {
                return Err(AuthError::Config(format!(
                    "AUTH_DEPLOYMENT_MODE={mode}, but the federation-mode cluster was configured"
                )));
            }
        }
        let session_store = self.session_store.load(Ordering::SeqCst);
        if !self.is_authority && !session_store {
            return Err(AuthError::Config(format!(
                "federation mode: only the authority '{}' keeps users; build this service \
                 with `Federation::session_store_repositories(..)`",
                self.settings
                    .federation
                    .authority_service
                    .clone()
                    .unwrap_or_default()
            )));
        }
        if session_store && self.is_authority {
            return Err(AuthError::Config(
                "a session store is for services other than the authority, in federation mode"
                    .into(),
            ));
        }
        self.fence
            .set(ctx.serving_fence())
            .map_err(|_| AuthError::Config("extension already attached".into()))?;
        ctx.subscribe(self.publisher.clone());
        if session_store {
            ctx.provides_permission_service();
        }
        Ok(())
    }

    fn assemble(&self, ctx: &mut AssembleContext<'_>) -> Result<(), AuthError> {
        let core = ctx.core().clone();
        let settings = &self.settings;
        if self.session_store.load(Ordering::SeqCst) {
            ctx.replace_permissions(Arc::new(SnapshotPermissions::new(
                self.authority.clone(),
                self.store.clone(),
                core.catalog().clone(),
            )));
            ctx.replace_accounts(Arc::new(SnapshotAccountSource::new(self.store.clone())));
            ctx.load_catalog_at_start();
        }
        let fence = self.fence.get().expect("configured first").clone();
        let cluster = Arc::new(FederationClusterService::new(
            Arc::new(MeshState::new(
                local_node(settings, core.node_id(), core.clock())?,
                fence,
            )),
            EnvelopeSigner::new(settings.cluster.secret.clone().ok_or_else(|| {
                AuthError::Config("missing AUTH_CLUSTER_SECRET (federation mode)".into())
            })?),
            self.transport.clone(),
            self.delay.clone().unwrap_or_else(|| Arc::new(NoDelay)),
            self.nodes.clone(),
            ReplicatedMemory {
                denylist: core.denylist().clone(),
                keyring: core.keyring().clone(),
                catalog: core.catalog().clone(),
                permissions: ctx.permissions().clone(),
                clock: core.clock().clone(),
            },
            &settings.cluster,
            settings.cluster.self_fence.unwrap_or(SelfFence::Quorum) == SelfFence::Quorum,
            self.on_fenced
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
        ));
        self.publisher.attach(&cluster);
        self.authority.attach(&cluster);

        let engine = Arc::new(FederationEngine::new(
            core.config(),
            settings,
            self.store.clone(),
            cluster.clone(),
            core.denylist().clone(),
            core.keyring().clone(),
            core.catalog().clone(),
            ctx.permissions().clone(),
            core.revocation().clone(),
            core.clock().clone(),
            core.entry_ttl(),
            core.node_id(),
        )?);
        let hooks: Arc<dyn SyncHooks> = engine.clone();
        cluster.set_hooks(&hooks);
        if !self.is_authority {
            ctx.set_refresh_gate(engine.clone())?;
        }
        // Strong references: the cluster holds the engine only weakly.
        let _ = self.cluster.set(cluster);
        let _ = self.engine.set(engine);
        Ok(())
    }

    fn decorate(&self, ctx: &mut DecorateContext<'_>) -> Result<(), AuthError> {
        let core = ctx.core().clone();
        let engine = self.engine.get().expect("assembled first");
        if self.is_authority {
            // The authority republishes snapshots after identity writes.
            let producer = Arc::new(SnapshotProducer::new(
                ctx.accounts().clone(),
                self.store.clone(),
                core.repositories().user_roles.clone(),
                ctx.permissions().clone(),
                core.config().authz.mode.uses_permissions(),
            ));
            engine.set_producer(producer.clone());
            *ctx.users() = Arc::new(ProducingUsers {
                inner: ctx.users().clone(),
                producer: producer.clone(),
            });
            *ctx.roles() = Arc::new(ProducingRoles {
                inner: ctx.roles().clone(),
                producer: producer.clone(),
            });
            *ctx.permissions() = Arc::new(ProducingPermissions {
                inner: ctx.permissions().clone(),
                producer: producer.clone(),
            });
            *ctx.authentication() = Arc::new(ProducingLogin {
                inner: ctx.authentication().clone(),
                producer: producer.clone(),
                decoder: core.decoder().clone(),
                clock: core.clock().clone(),
            });
            let _ = self.producer.set(producer);
        } else {
            // Session stores refuse identity writes and logins.
            *ctx.users() = Arc::new(NotAuthorityUsers(self.authority.clone()));
            *ctx.roles() = Arc::new(NotAuthorityRoles(self.authority.clone()));
            *ctx.authentication() = Arc::new(NotAuthorityLogin {
                authority: self.authority.clone(),
                inner: ctx.authentication().clone(),
            });
        }
        // Outermost: a fenced instance refuses every session operation.
        let fence = self.fence.get().expect("configured first").clone();
        *ctx.authentication() = Arc::new(FencedAuthentication {
            inner: ctx.authentication().clone(),
            fenced: fence.clone(),
        });
        *ctx.revocation() = Arc::new(FencedRevocation {
            inner: ctx.revocation().clone(),
            fenced: fence,
        });
        Ok(())
    }

    async fn start(&self) -> Result<Option<ExtensionReport>, AuthError> {
        // The feed is on before anyone can pull it.
        self.engine_built()?.start().await?;
        if let Some(producer) = self.producer.get() {
            producer.catalog_changed().await?;
        }
        let report = self.built()?.start().await?;
        Ok(Some(ExtensionReport::new(CLUSTER_EXTENSION, report)))
    }

    async fn tick(&self) -> Result<Option<ExtensionReport>, AuthError> {
        let report = self.built()?.tick().await?;
        if !self.is_fenced() {
            self.engine_built()?.tick().await?;
        }
        Ok(Some(ExtensionReport::new(CLUSTER_EXTENSION, report)))
    }

    async fn shutdown(&self) -> Result<(), AuthError> {
        self.built()?.leave().await
    }
}
