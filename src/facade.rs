//! [`AuthLib`] — a single entry point that wires every service from the
//! adapters supplied by the host application.
//!
//! ```rust,ignore
//! let repos = Repositories {
//!     users: Arc::new(PgUserRepository::new(pool.clone())),
//!     roles: Arc::new(PgRoleRepository::new(pool.clone())),
//!     user_roles: Arc::new(PgUserRoleRepository::new(pool.clone())),
//!     sessions: Arc::new(PgSessionRepository::new(pool.clone())),
//!     revocations: Arc::new(PgRevocationRepository::new(pool.clone())),
//!     keys: Arc::new(PgKeyRepository::new(pool.clone())),
//! }; // or `auth_lib_postgres::repositories(&pool)`
//! let auth = AuthLib::builder(config, repos)
//!     .permissions(Arc::new(PgPermissionRepository::new(pool.clone()))) // permission modes
//!     .cluster(Arc::new(MyHttpTransport::new()), Arc::new(PgNodeRepository::new(pool)))
//!     .build()?;
//!
//! auth.start().await?;                  // once: load state, join the cluster
//! // every `config.cluster.heartbeat`:  auth.tick().await?;
//! // inbound cluster endpoint:         auth.cluster().unwrap().receive(envelope).await?;
//! // on shutdown:                      auth.shutdown().await?;
//! let pair = auth.authentication().login(credentials, ctx).await?;
//! ```

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::{
    access::{RoleRepository, RoleService, RoleServiceImpl, UserRoleRepository},
    authentication::{AuthenticationService, AuthenticationServiceImpl, SessionRepository},
    authorization::{
        Authorizer, AuthorizerImpl, AuthzClaimsProviderImpl, BitsetPermissionCodec, CatalogCache,
        PermissionCodec, PermissionRepository, PermissionService, PermissionServiceImpl,
    },
    clock::{Clock, SystemClock},
    config::AuthConfig,
    credentials::PasswordHasher,
    error::AuthError,
    events::{EventPublisher, NoopPublisher},
    token::{
        AccessTokenDecoder, AccessTokenIssuer, Denylist, KeyRepository, KeyRing, RefreshTokenCodec,
        RevocationRepository, TokenRevocationService, TokenRevocationServiceImpl, TokenVerifier,
    },
    user::{UserRepository, UserService, UserServiceImpl},
};

#[cfg(feature = "cluster")]
use crate::cluster::{
    ClusterMessenger, ClusterPublisher, ClusterReport, ClusterService, ClusterServiceImpl,
    ClusterState, ClusterTransport, EnvelopeSigner, NodeInfo, NodeRepository,
};
#[cfg(feature = "crypto")]
use crate::token::{KeyService, KeyServiceImpl};

/// What [`AuthLib::start`] loaded.
#[derive(Debug, Clone, Default)]
pub struct StartReport {
    pub revocations_loaded: usize,
    pub keys_loaded: usize,
    #[cfg(feature = "cluster")]
    pub cluster: Option<ClusterReport>,
}

/// What one [`AuthLib::tick`] did.
#[derive(Debug, Clone, Default)]
pub struct TickReport {
    /// Revocations this instance enforced (covered tokens were presented).
    pub enforced: usize,
    /// Expired denylist entries dropped.
    pub pruned: usize,
    #[cfg(feature = "cluster")]
    pub cluster: Option<ClusterReport>,
}

/// All auth-lib services, ready to use.
pub struct AuthLib {
    config: AuthConfig,
    node_id: Uuid,
    clock: Arc<dyn Clock>,
    keyring: Arc<KeyRing>,
    /// This instance's own verifying key (built-in issuer), published at start.
    #[cfg_attr(not(feature = "crypto"), allow(dead_code))]
    own_verifying_key: Option<[u8; 32]>,
    #[cfg(feature = "crypto")]
    keys: Arc<dyn KeyService>,
    #[cfg(feature = "cluster")]
    cluster: Option<Arc<dyn ClusterService>>,
    users: Arc<dyn UserService>,
    roles: Arc<dyn RoleService>,
    permissions: Arc<dyn PermissionService>,
    authorizer: Arc<dyn Authorizer>,
    authentication: Arc<dyn AuthenticationService>,
    revocation: Arc<dyn TokenRevocationService>,
    verifier: Arc<TokenVerifier>,
}

impl AuthLib {
    pub fn builder(config: AuthConfig, repos: Repositories) -> AuthLibBuilder {
        AuthLibBuilder::new(config, repos)
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }
    pub fn users(&self) -> &dyn UserService {
        self.users.as_ref()
    }
    pub fn roles(&self) -> &dyn RoleService {
        self.roles.as_ref()
    }
    /// Permission catalog and grants (`permissions` / `combined` modes).
    pub fn permissions(&self) -> &dyn PermissionService {
        self.permissions.as_ref()
    }
    /// Request-time authorization checks from a verified token — no I/O.
    pub fn authorizer(&self) -> &dyn Authorizer {
        self.authorizer.as_ref()
    }
    pub fn authentication(&self) -> &dyn AuthenticationService {
        self.authentication.as_ref()
    }
    pub fn revocation(&self) -> &dyn TokenRevocationService {
        self.revocation.as_ref()
    }
    /// Access-token verification — no I/O.
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }
    pub fn denylist(&self) -> &Arc<Denylist> {
        self.verifier.denylist()
    }
    /// Verifying keys accepted (and key ids rejected) — no I/O.
    pub fn keyring(&self) -> &Arc<KeyRing> {
        &self.keyring
    }
    /// Verifying-key distribution and signing-key revocation.
    #[cfg(feature = "crypto")]
    pub fn keys(&self) -> &dyn KeyService {
        self.keys.as_ref()
    }
    /// The cluster, when a transport was configured.
    #[cfg(feature = "cluster")]
    pub fn cluster(&self) -> Option<&dyn ClusterService> {
        self.cluster.as_deref()
    }
    /// This instance's id (also the cluster node id).
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }

    /// Call once at startup: load the stored revocations, keys and (in
    /// permission modes) the catalog into memory, join the cluster, and
    /// publish this instance's verifying key.
    pub async fn start(&self) -> Result<StartReport, AuthError> {
        #[cfg(feature = "crypto")]
        let keys_loaded = self.keys.load().await?;
        #[cfg(not(feature = "crypto"))]
        let keys_loaded = 0;
        let revocations_loaded = self.revocation.load().await?;
        if self.config.authz.mode.uses_permissions() {
            self.permissions.reload_catalog().await?;
        }
        #[cfg(feature = "cluster")]
        let cluster = match &self.cluster {
            Some(cluster) => Some(cluster.start().await?),
            None => None,
        };
        // After joining, so the peers receive the key event too.
        #[cfg(feature = "crypto")]
        if let Some(key) = self.own_verifying_key {
            self.keys.publish_verifying_key(key).await?;
        }
        Ok(StartReport {
            revocations_loaded,
            keys_loaded,
            #[cfg(feature = "cluster")]
            cluster,
        })
    }

    /// Call every `config.cluster.heartbeat` (also without a cluster):
    /// enforce revocations whose tokens were presented, drop expired
    /// denylist entries, and run one cluster round.
    pub async fn tick(&self) -> Result<TickReport, AuthError> {
        let enforced = self.revocation.enforce_pending().await?;
        let pruned = self.denylist().prune(self.clock.now());
        #[cfg(feature = "cluster")]
        let cluster = match &self.cluster {
            Some(cluster) => Some(cluster.tick().await?),
            None => None,
        };
        Ok(TickReport {
            enforced,
            pruned,
            #[cfg(feature = "cluster")]
            cluster,
        })
    }

    /// Call on graceful shutdown: leave the cluster.
    pub async fn shutdown(&self) -> Result<(), AuthError> {
        #[cfg(feature = "cluster")]
        if let Some(cluster) = &self.cluster {
            cluster.leave().await?;
        }
        Ok(())
    }
}

/// The storage every instance needs.  Every field is required, so a missing
/// repository is a compile error rather than a startup failure.
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use auth_lib::Repositories;
/// # fn missing(users: Arc<dyn auth_lib::user::UserRepository>) {
/// let repos = Repositories { users }; // roles, user_roles, sessions, … missing
/// # }
/// ```
pub struct Repositories {
    pub users: Arc<dyn UserRepository>,
    pub roles: Arc<dyn RoleRepository>,
    pub user_roles: Arc<dyn UserRoleRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub revocations: Arc<dyn RevocationRepository>,
    /// Published verifying keys (unused without the `crypto` feature).
    pub keys: Arc<dyn KeyRepository>,
}

/// Builds an [`AuthLib`] from the required [`Repositories`] plus the
/// optional parts: the permission repository (permission modes), the
/// cluster, and replacements for the default components.
pub struct AuthLibBuilder {
    config: AuthConfig,
    repos: Repositories,
    #[cfg(feature = "cluster")]
    cluster: Option<(Arc<dyn ClusterTransport>, Arc<dyn NodeRepository>)>,
    permissions: Option<Arc<dyn PermissionRepository>>,
    permission_codec: Option<Arc<dyn PermissionCodec>>,
    password_hasher: Option<Arc<dyn PasswordHasher>>,
    access_issuer: Option<Arc<dyn AccessTokenIssuer>>,
    access_decoder: Option<Arc<dyn AccessTokenDecoder>>,
    refresh_codec: Option<Arc<dyn RefreshTokenCodec>>,
    denylist: Option<Arc<Denylist>>,
    clock: Option<Arc<dyn Clock>>,
}

impl AuthLibBuilder {
    pub fn new(config: AuthConfig, repos: Repositories) -> Self {
        Self {
            config,
            repos,
            #[cfg(feature = "cluster")]
            cluster: None,
            permissions: None,
            permission_codec: None,
            password_hasher: None,
            access_issuer: None,
            access_decoder: None,
            refresh_codec: None,
            denylist: None,
            clock: None,
        }
    }

    /// Join a cluster: `transport` reaches the other instances, `nodes` is
    /// the registry read at startup.  Requires `AUTH_CLUSTER_SECRET`, a
    /// port and an address to advertise.  Without it the instance runs
    /// standalone.
    #[cfg(feature = "cluster")]
    pub fn cluster(
        mut self,
        transport: Arc<dyn ClusterTransport>,
        nodes: Arc<dyn NodeRepository>,
    ) -> Self {
        self.cluster = Some((transport, nodes));
        self
    }
    /// Required when `AUTH_AUTHZ_MODE` is `permissions` or `combined`.
    pub fn permissions(mut self, repo: Arc<dyn PermissionRepository>) -> Self {
        self.permissions = Some(repo);
        self
    }
    /// Defaults to [`BitsetPermissionCodec`] (format v1).
    pub fn permission_codec(mut self, codec: Arc<dyn PermissionCodec>) -> Self {
        self.permission_codec = Some(codec);
        self
    }
    /// Defaults to `Argon2Hasher` (feature `argon2`).
    pub fn password_hasher(mut self, hasher: Arc<dyn PasswordHasher>) -> Self {
        self.password_hasher = Some(hasher);
        self
    }
    /// Defaults to `Ed25519Issuer` from `config.jwt` (feature `crypto`).
    pub fn access_issuer(mut self, issuer: Arc<dyn AccessTokenIssuer>) -> Self {
        self.access_issuer = Some(issuer);
        self
    }
    /// Defaults to `Ed25519Decoder` from `config.jwt` (feature `crypto`).
    pub fn access_decoder(mut self, decoder: Arc<dyn AccessTokenDecoder>) -> Self {
        self.access_decoder = Some(decoder);
        self
    }
    /// Defaults to `HmacRefreshCodec` from `config.session` (feature `crypto`).
    pub fn refresh_codec(mut self, codec: Arc<dyn RefreshTokenCodec>) -> Self {
        self.refresh_codec = Some(codec);
        self
    }
    /// Share a denylist (e.g. one also fed by a message bus).  Defaults to a
    /// new, empty one.
    pub fn denylist(mut self, denylist: Arc<Denylist>) -> Self {
        self.denylist = Some(denylist);
        self
    }
    /// Local clock for stateless token checks.  Defaults to [`SystemClock`].
    /// Persisted timestamps always come from the repositories' store.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Wire every service.
    ///
    /// # Errors
    /// [`AuthError::Config`] if the permission repository (permission modes),
    /// a key or a secret is missing.
    pub fn build(self) -> Result<AuthLib, AuthError> {
        let Repositories {
            users,
            roles,
            user_roles,
            sessions,
            revocations,
            keys: key_repo,
        } = self.repos;
        #[cfg(not(feature = "crypto"))]
        let _ = key_repo;
        let mode = self.config.authz.mode;
        if mode.uses_permissions() && self.permissions.is_none() {
            return Err(AuthError::Config(format!(
                "missing adapter: permissions (required by authorization mode {mode:?})"
            )));
        }
        let hasher = match self.password_hasher {
            Some(h) => h,
            None => defaults::hasher()?,
        };
        let (issuer, own_verifying_key) = match self.access_issuer {
            Some(i) => (i, None),
            None => defaults::issuer(&self.config)?,
        };
        let keyring = Arc::new(defaults::keyring(&self.config, own_verifying_key)?);
        let decoder = match self.access_decoder {
            Some(d) => d,
            None => defaults::decoder(&self.config, keyring.clone())?,
        };
        let refresh_codec = match self.refresh_codec {
            Some(c) => c,
            None => defaults::refresh_codec(&self.config)?,
        };
        let denylist = self.denylist.unwrap_or_default();
        let clock = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let node_id = Uuid::new_v4();

        // Events go to the cluster when there is one, nowhere otherwise.
        #[cfg(feature = "cluster")]
        let messenger = match self.cluster.as_ref() {
            Some((transport, _)) => Some(Arc::new(ClusterMessenger::new(
                Arc::new(ClusterState::new(local_node(
                    &self.config,
                    node_id,
                    &clock,
                )?)),
                EnvelopeSigner::new(self.config.cluster.secret.clone().ok_or_else(|| {
                    AuthError::Config("missing AUTH_CLUSTER_SECRET (cluster configured)".into())
                })?),
                transport.clone(),
                clock.clone(),
            ))),
            None => None,
        };
        #[cfg(feature = "cluster")]
        let events: Arc<dyn EventPublisher> = match &messenger {
            Some(m) => Arc::new(ClusterPublisher::new(m.clone())),
            None => Arc::new(NoopPublisher),
        };
        #[cfg(not(feature = "cluster"))]
        let events: Arc<dyn EventPublisher> = Arc::new(NoopPublisher);

        let verifier = Arc::new(TokenVerifier::new(
            decoder.clone(),
            denylist.clone(),
            clock.clone(),
        ));
        let catalog = Arc::new(CatalogCache::new());
        let codec = self
            .permission_codec
            .unwrap_or_else(|| Arc::new(BitsetPermissionCodec));
        let authz_claims = Arc::new(AuthzClaimsProviderImpl::new(
            mode,
            self.permissions.clone(),
            codec.clone(),
            catalog.clone(),
        ));

        let entry_ttl: Duration = self.config.jwt.access_token_ttl + self.config.jwt.leeway;
        let revocation: Arc<dyn TokenRevocationService> =
            Arc::new(TokenRevocationServiceImpl::new(
                sessions.clone(),
                revocations.clone(),
                denylist.clone(),
                decoder.clone(),
                refresh_codec.clone(),
                clock.clone(),
                events.clone(),
                node_id,
                entry_ttl,
            ));
        let permissions: Arc<dyn PermissionService> = Arc::new(PermissionServiceImpl::new(
            mode,
            self.permissions,
            catalog.clone(),
            events.clone(),
        ));

        #[cfg(feature = "crypto")]
        let keys: Arc<dyn KeyService> = Arc::new(KeyServiceImpl::new(
            key_repo,
            keyring.clone(),
            events.clone(),
            clock.clone(),
            node_id,
        ));
        #[cfg(feature = "cluster")]
        let cluster: Option<Arc<dyn ClusterService>> = match (messenger, self.cluster) {
            (Some(messenger), Some((_, nodes))) => Some(Arc::new(ClusterServiceImpl::new(
                messenger,
                nodes,
                denylist.clone(),
                keyring.clone(),
                catalog.clone(),
                permissions.clone(),
                clock.clone(),
                &self.config.cluster,
            ))),
            _ => None,
        };

        Ok(AuthLib {
            users: Arc::new(UserServiceImpl::new(
                users.clone(),
                hasher.clone(),
                revocation.clone(),
                self.config.password.clone(),
            )),
            roles: Arc::new(RoleServiceImpl::new(roles, user_roles, mode)),
            permissions,
            authorizer: Arc::new(AuthorizerImpl::new(catalog, codec)),
            authentication: Arc::new(AuthenticationServiceImpl::new(
                users,
                sessions,
                revocation.clone(),
                authz_claims,
                hasher,
                issuer,
                decoder,
                refresh_codec,
                verifier.clone(),
                keyring.clone(),
                clock.clone(),
                self.config.clone(),
            )),
            revocation,
            verifier,
            node_id,
            clock,
            keyring,
            own_verifying_key,
            #[cfg(feature = "crypto")]
            keys,
            #[cfg(feature = "cluster")]
            cluster,
            config: self.config,
        })
    }
}

/// This instance as advertised to peers (`AUTH_CLUSTER_*`).
#[cfg(feature = "cluster")]
fn local_node(
    config: &AuthConfig,
    node_id: Uuid,
    clock: &Arc<dyn Clock>,
) -> Result<NodeInfo, AuthError> {
    let c = &config.cluster;
    if c.advertise_ip.is_none() && c.advertise_dns.is_none() {
        return Err(AuthError::Config(
            "cluster configured: set AUTH_CLUSTER_ADVERTISE_IP or AUTH_CLUSTER_ADVERTISE_DNS"
                .into(),
        ));
    }
    Ok(NodeInfo {
        node_id,
        service: c.service.clone(),
        ip: c.advertise_ip,
        dns_name: c.advertise_dns.clone(),
        port: c.advertise_port.ok_or_else(|| {
            AuthError::Config("cluster configured: set AUTH_CLUSTER_ADVERTISE_PORT".into())
        })?,
        version: env!("CARGO_PKG_VERSION").into(),
        started_at: clock.now(),
    })
}

/// Feature-dependent defaults.  Without the feature, the component must be
/// supplied explicitly.
mod defaults {
    use super::*;

    /// An issuer plus its verifying key, when the format exposes one.
    pub type IssuerWithKey = (Arc<dyn AccessTokenIssuer>, Option<[u8; 32]>);

    #[cfg(feature = "argon2")]
    pub fn hasher() -> Result<Arc<dyn PasswordHasher>, AuthError> {
        Ok(Arc::new(crate::credentials::Argon2Hasher))
    }
    #[cfg(not(feature = "argon2"))]
    pub fn hasher() -> Result<Arc<dyn PasswordHasher>, AuthError> {
        Err(missing("password_hasher", "argon2"))
    }

    /// The built-in issuer and its verifying key.
    #[cfg(feature = "crypto")]
    pub fn issuer(config: &AuthConfig) -> Result<IssuerWithKey, AuthError> {
        let issuer = crate::token::jwt::Ed25519Issuer::from_config(&config.jwt)?;
        let key = issuer.verifying_key();
        Ok((Arc::new(issuer), Some(key)))
    }
    /// Configured verifying keys plus this instance's own key.
    #[cfg(feature = "crypto")]
    pub fn keyring(config: &AuthConfig, own: Option<[u8; 32]>) -> Result<KeyRing, AuthError> {
        let mut keys = crate::token::jwt::configured_verifying_keys(&config.jwt);
        keys.extend(own);
        crate::token::jwt::keyring_from_keys(&keys)
    }
    #[cfg(feature = "crypto")]
    pub fn decoder(
        config: &AuthConfig,
        keyring: Arc<KeyRing>,
    ) -> Result<Arc<dyn AccessTokenDecoder>, AuthError> {
        Ok(Arc::new(crate::token::jwt::Ed25519Decoder::with_keyring(
            keyring,
            config.jwt.issuer.clone(),
            config.jwt.leeway,
        )))
    }
    #[cfg(feature = "crypto")]
    pub fn refresh_codec(config: &AuthConfig) -> Result<Arc<dyn RefreshTokenCodec>, AuthError> {
        Ok(Arc::new(
            crate::token::refresh::HmacRefreshCodec::from_config(&config.session)?,
        ))
    }

    #[cfg(not(feature = "crypto"))]
    pub fn issuer(_: &AuthConfig) -> Result<IssuerWithKey, AuthError> {
        Err(missing("access_issuer", "crypto"))
    }
    #[cfg(not(feature = "crypto"))]
    pub fn keyring(_: &AuthConfig, _: Option<[u8; 32]>) -> Result<KeyRing, AuthError> {
        Ok(KeyRing::new())
    }
    #[cfg(not(feature = "crypto"))]
    pub fn decoder(
        _: &AuthConfig,
        _: Arc<KeyRing>,
    ) -> Result<Arc<dyn AccessTokenDecoder>, AuthError> {
        Err(missing("access_decoder", "crypto"))
    }
    #[cfg(not(feature = "crypto"))]
    pub fn refresh_codec(_: &AuthConfig) -> Result<Arc<dyn RefreshTokenCodec>, AuthError> {
        Err(missing("refresh_codec", "crypto"))
    }

    #[allow(dead_code)] // unused when every default feature is enabled
    fn missing(component: &str, feature: &str) -> AuthError {
        AuthError::Config(format!(
            "missing component: {component} (enable the `{feature}` feature for a default)"
        ))
    }
}
