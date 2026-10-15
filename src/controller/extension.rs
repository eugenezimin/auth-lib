//! [`Extension`] — the port through which optional crates (e.g. a cluster)
//! plug into [`ZAuth`](crate::ZAuth) without z-auth knowing them.
//!
//! The host registers extensions on the builder:
//!
//! ```rust,ignore
//! let cluster = Arc::new(SharedCluster::new(settings, transport, nodes)); // z-auth-cluster
//! let auth = ZAuth::builder(config, repos).extension(cluster.clone()).build()?;
//! ```
//!
//! [`ZAuthBuilder::build`](crate::ZAuthBuilder::build) calls every
//! extension three times, in registration order:
//!
//! 1. [`configure`](Extension::configure), before any service exists —
//!    subscribe to domain events (revocations, enforcements, keys, catalog;
//!    see [`eventing`](crate::eventing)) and claim a serving fence;
//! 2. [`assemble`](Extension::assemble), once the shared in-memory state
//!    (denylist, key ring, catalog) and the revocation, key and permission
//!    services exist — replace the permission service or the refresh
//!    account source, install a refresh gate;
//! 3. [`decorate`](Extension::decorate), once every service exists — wrap
//!    or replace the public ones.  Later extensions wrap outside earlier
//!    ones.
//!
//! [`ZAuth::start`](crate::ZAuth::start), [`tick`](crate::ZAuth::tick)
//! and [`shutdown`](crate::ZAuth::shutdown) drive the extensions too.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::conf::config::AuthConfig;
use crate::controller::repositories::Repositories;
use crate::eventing::EventPublisher;
use crate::identity::access::RoleService;
use crate::identity::user::UserService;
use crate::security::authentication::{AuthenticationService, RefreshAccountSource, RefreshGate};
use crate::security::authorization::{CatalogCache, PermissionRepository, PermissionService};
use crate::security::token::{
    AccessTokenDecoder, Denylist, KeyRing, TokenRevocationService, TokenVerifier,
};
use crate::utils::clock::Clock;
use crate::utils::error::AuthError;
use crate::utils::fence::ServingFence;

/// An optional component wired into [`ZAuth`](crate::ZAuth) at build
/// time and driven by its lifecycle.  Every method has a no-op default.
#[async_trait]
pub trait Extension: Send + Sync {
    /// Names the extension in reports and errors.
    fn name(&self) -> &'static str;

    /// Phase 1: before any service exists.
    fn configure(&self, _ctx: &mut ConfigureContext<'_>) -> Result<(), AuthError> {
        Ok(())
    }

    /// Phase 2: the shared state and the revocation, key and permission
    /// services exist; authentication, users and roles do not yet.
    fn assemble(&self, _ctx: &mut AssembleContext<'_>) -> Result<(), AuthError> {
        Ok(())
    }

    /// Phase 3: every service exists; wrap or replace the public ones.
    fn decorate(&self, _ctx: &mut DecorateContext<'_>) -> Result<(), AuthError> {
        Ok(())
    }

    /// After z-auth loaded its state, before it publishes its own
    /// verifying key.
    async fn start(&self) -> Result<Option<ExtensionReport>, AuthError> {
        Ok(None)
    }

    /// After z-auth enforced pending revocations and pruned the denylist.
    async fn tick(&self) -> Result<Option<ExtensionReport>, AuthError> {
        Ok(None)
    }

    /// On graceful shutdown, in reverse registration order.
    async fn shutdown(&self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Phase 1: what an extension may do before any service exists.
pub struct ConfigureContext<'a> {
    pub(crate) config: &'a AuthConfig,
    pub(crate) node_id: Uuid,
    pub(crate) clock: &'a Arc<dyn Clock>,
    pub(crate) subscribers: Vec<Arc<dyn EventPublisher>>,
    pub(crate) fence: Option<ServingFence>,
    pub(crate) provides_permissions: bool,
}

impl ConfigureContext<'_> {
    pub fn config(&self) -> &AuthConfig {
        self.config
    }
    /// This instance's id.
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }
    pub fn clock(&self) -> &Arc<dyn Clock> {
        self.clock
    }
    /// Receive every domain event z-auth publishes: new and enforced
    /// revocations (the denylist changes), verifying keys, revoked signing
    /// keys and catalog changes.
    pub fn subscribe(&mut self, events: Arc<dyn EventPublisher>) {
        self.subscribers.push(events);
    }
    /// The fence honoured by the token verifier, [`ZAuth::tick`] and
    /// [`ZAuth::is_fenced`].  Every caller gets the same one.
    ///
    /// [`ZAuth::tick`]: crate::ZAuth::tick
    /// [`ZAuth::is_fenced`]: crate::ZAuth::is_fenced
    pub fn serving_fence(&mut self) -> ServingFence {
        self.fence.get_or_insert_with(ServingFence::new).clone()
    }
    /// This extension supplies the permission service (in
    /// [`assemble`](Extension::assemble)), so permission modes need no
    /// permission repository.
    pub fn provides_permission_service(&mut self) {
        self.provides_permissions = true;
    }
}

/// The shared state and core services, available from phase 2 on.
#[derive(Clone)]
pub struct CoreHandles {
    pub(crate) config: AuthConfig,
    pub(crate) node_id: Uuid,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) entry_ttl: Duration,
    pub(crate) denylist: Arc<Denylist>,
    pub(crate) keyring: Arc<KeyRing>,
    pub(crate) catalog: Arc<CatalogCache>,
    pub(crate) decoder: Arc<dyn AccessTokenDecoder>,
    pub(crate) verifier: Arc<TokenVerifier>,
    pub(crate) repositories: Repositories,
    pub(crate) permission_repository: Option<Arc<dyn PermissionRepository>>,
    pub(crate) revocation: Arc<dyn TokenRevocationService>,
}

impl CoreHandles {
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }
    /// How long a denylist entry lives (access-token TTL plus leeway).
    pub fn entry_ttl(&self) -> Duration {
        self.entry_ttl
    }
    pub fn denylist(&self) -> &Arc<Denylist> {
        &self.denylist
    }
    pub fn keyring(&self) -> &Arc<KeyRing> {
        &self.keyring
    }
    pub fn catalog(&self) -> &Arc<CatalogCache> {
        &self.catalog
    }
    pub fn decoder(&self) -> &Arc<dyn AccessTokenDecoder> {
        &self.decoder
    }
    pub fn verifier(&self) -> &Arc<TokenVerifier> {
        &self.verifier
    }
    /// The repositories the builder was given.
    pub fn repositories(&self) -> &Repositories {
        &self.repositories
    }
    pub fn permission_repository(&self) -> Option<&Arc<dyn PermissionRepository>> {
        self.permission_repository.as_ref()
    }
    /// The revocation service as used inside z-auth (never wrapped by
    /// [`decorate`](Extension::decorate)).
    pub fn revocation(&self) -> &Arc<dyn TokenRevocationService> {
        &self.revocation
    }
}

/// Phase 2: replace the permission service or the refresh account source,
/// install a refresh gate.
pub struct AssembleContext<'a> {
    pub(crate) core: &'a CoreHandles,
    pub(crate) permissions: Arc<dyn PermissionService>,
    pub(crate) accounts: Arc<dyn RefreshAccountSource>,
    pub(crate) gate: Option<Arc<dyn RefreshGate>>,
    pub(crate) load_catalog: bool,
}

impl AssembleContext<'_> {
    pub fn core(&self) -> &CoreHandles {
        self.core
    }
    pub fn permissions(&self) -> &Arc<dyn PermissionService> {
        &self.permissions
    }
    /// Every service built from here on uses `permissions`.
    pub fn replace_permissions(&mut self, permissions: Arc<dyn PermissionService>) {
        self.permissions = permissions;
    }
    /// Where a refresh reads the account (activity, authorization claims).
    pub fn accounts(&self) -> &Arc<dyn RefreshAccountSource> {
        &self.accounts
    }
    pub fn replace_accounts(&mut self, accounts: Arc<dyn RefreshAccountSource>) {
        self.accounts = accounts;
    }
    /// Consulted on every refresh.  At most one per instance.
    pub fn set_refresh_gate(&mut self, gate: Arc<dyn RefreshGate>) -> Result<(), AuthError> {
        if self.gate.is_some() {
            return Err(AuthError::Config(
                "a refresh gate is already installed by another extension".into(),
            ));
        }
        self.gate = Some(gate);
        Ok(())
    }
    /// Load the permission catalog at start even outside permission modes.
    pub fn load_catalog_at_start(&mut self) {
        self.load_catalog = true;
    }
}

/// Phase 3: wrap or replace the public services.
pub struct DecorateContext<'a> {
    pub(crate) core: &'a CoreHandles,
    pub(crate) accounts: &'a Arc<dyn RefreshAccountSource>,
    pub(crate) users: Arc<dyn UserService>,
    pub(crate) roles: Arc<dyn RoleService>,
    pub(crate) permissions: Arc<dyn PermissionService>,
    pub(crate) authentication: Arc<dyn AuthenticationService>,
    pub(crate) revocation: Arc<dyn TokenRevocationService>,
}

impl DecorateContext<'_> {
    pub fn core(&self) -> &CoreHandles {
        self.core
    }
    /// The refresh account source in use.
    pub fn accounts(&self) -> &Arc<dyn RefreshAccountSource> {
        self.accounts
    }
    pub fn users(&mut self) -> &mut Arc<dyn UserService> {
        &mut self.users
    }
    pub fn roles(&mut self) -> &mut Arc<dyn RoleService> {
        &mut self.roles
    }
    pub fn permissions(&mut self) -> &mut Arc<dyn PermissionService> {
        &mut self.permissions
    }
    pub fn authentication(&mut self) -> &mut Arc<dyn AuthenticationService> {
        &mut self.authentication
    }
    /// The public revocation service ([`ZAuth::revocation`]).
    ///
    /// [`ZAuth::revocation`]: crate::ZAuth::revocation
    pub fn revocation(&mut self) -> &mut Arc<dyn TokenRevocationService> {
        &mut self.revocation
    }
}

/// What an extension reports from [`start`](Extension::start) or
/// [`tick`](Extension::tick); read it back with [`get`](Self::get).
#[derive(Clone)]
pub struct ExtensionReport {
    extension: &'static str,
    data: Arc<dyn Any + Send + Sync>,
    debug: Arc<dyn Fn(&mut fmt::Formatter<'_>) -> fmt::Result + Send + Sync>,
}

impl ExtensionReport {
    pub fn new<T: Any + fmt::Debug + Send + Sync>(extension: &'static str, data: T) -> Self {
        let data = Arc::new(data);
        let shown = data.clone();
        Self {
            extension,
            data,
            debug: Arc::new(move |f| fmt::Debug::fmt(&*shown, f)),
        }
    }
    /// The reporting extension's [`name`](Extension::name).
    pub fn extension(&self) -> &'static str {
        self.extension
    }
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.data.downcast_ref()
    }
}

impl fmt::Debug for ExtensionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.extension)?;
        (self.debug)(f)
    }
}

/// The first report of type `T`.
pub(crate) fn find<T: Any>(reports: &[ExtensionReport]) -> Option<&T> {
    reports.iter().find_map(ExtensionReport::get)
}
