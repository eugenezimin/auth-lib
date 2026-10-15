//! [`ZAuth`] — a single entry point that wires every service from the
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
//! }; // or `z_auth_postgres::repositories(&pool)`
//! let auth = ZAuth::builder(config, repos)
//!     .permissions(Arc::new(PgPermissionRepository::new(pool.clone()))) // permission modes
//!     .extension(cluster.clone()) // optional, e.g. z-auth-cluster
//!     .build()?;
//!
//! auth.start().await?;                  // once: load state, start the extensions
//! // periodically (e.g. every heartbeat): auth.tick().await?;
//! // on shutdown:                      auth.shutdown().await?;
//! let pair = auth.authentication().login(credentials, ctx).await?;
//! ```

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::conf::config::AuthConfig;
pub use crate::controller::repositories::Repositories;

use crate::controller::extension::{
    self, AssembleContext, ConfigureContext, CoreHandles, DecorateContext, Extension,
    ExtensionReport,
};
use crate::eventing::{EventPublisher, FanoutPublisher, NoopPublisher};
use crate::identity::access::{RoleService, RoleServiceImpl};
use crate::identity::credentials::PasswordHasher;
use crate::identity::user::{UserService, UserServiceImpl};
use crate::security::authentication::{
    AuthenticationService, AuthenticationServiceImpl, RefreshAccountSource, StoreAccountSource,
};
use crate::security::authorization::{
    Authorizer, AuthorizerImpl, AuthzClaimsProviderImpl, BitsetPermissionCodec, CatalogCache,
    PermissionCodec, PermissionRepository, PermissionService, PermissionServiceImpl,
};
use crate::security::token::{
    AccessTokenDecoder, AccessTokenIssuer, Denylist, KeyRing, RefreshTokenCodec,
    TokenRevocationService, TokenRevocationServiceImpl, TokenVerifier,
};
use crate::utils::clock::{Clock, SystemClock};
use crate::utils::error::AuthError;
use crate::utils::fence::ServingFence;

#[cfg(feature = "crypto")]
use crate::security::token::{KeyService, KeyServiceImpl};

/// What [`ZAuth::start`] loaded.
#[derive(Debug, Clone, Default)]
pub struct StartReport {
    pub revocations_loaded: usize,
    pub keys_loaded: usize,
    /// One per extension that reported.
    pub extensions: Vec<ExtensionReport>,
}

impl StartReport {
    /// The first extension report of type `T`.
    pub fn extension<T: Any>(&self) -> Option<&T> {
        extension::find(&self.extensions)
    }
}

/// What one [`ZAuth::tick`] did.
#[derive(Debug, Clone, Default)]
pub struct TickReport {
    /// Revocations this instance enforced (covered tokens were presented).
    pub enforced: usize,
    /// Expired denylist entries dropped.
    pub pruned: usize,
    /// One per extension that reported.
    pub extensions: Vec<ExtensionReport>,
}

impl TickReport {
    /// The first extension report of type `T`.
    pub fn extension<T: Any>(&self) -> Option<&T> {
        extension::find(&self.extensions)
    }
}

/// All z-auth services, ready to use.
pub struct ZAuth {
    config: AuthConfig,
    node_id: Uuid,
    clock: Arc<dyn Clock>,
    keyring: Arc<KeyRing>,
    /// This instance's own verifying key (built-in issuer), published at start.
    #[cfg_attr(not(feature = "crypto"), allow(dead_code))]
    own_verifying_key: Option<[u8; 32]>,
    #[cfg(feature = "crypto")]
    keys: Arc<dyn KeyService>,
    extensions: Vec<Arc<dyn Extension>>,
    /// Raised by an extension when this instance must stop serving.
    fence: Option<ServingFence>,
    /// Load the catalog at start even outside permission modes.
    load_catalog: bool,
    users: Arc<dyn UserService>,
    roles: Arc<dyn RoleService>,
    permissions: Arc<dyn PermissionService>,
    authorizer: Arc<dyn Authorizer>,
    authentication: Arc<dyn AuthenticationService>,
    revocation: Arc<dyn TokenRevocationService>,
    verifier: Arc<TokenVerifier>,
}

impl ZAuth {
    pub fn builder(config: AuthConfig, repos: Repositories) -> ZAuthBuilder {
        ZAuthBuilder::new(config, repos)
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
    /// This instance's id (also its node id in a cluster).
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }
    /// An extension fenced this instance: it refuses to serve and the host
    /// should restart it.
    pub fn is_fenced(&self) -> bool {
        self.fence.as_ref().is_some_and(ServingFence::is_fenced)
    }

    /// Call once at startup: load the stored revocations, keys and (in
    /// permission modes) the catalog into memory, start the extensions,
    /// and publish this instance's verifying key.
    pub async fn start(&self) -> Result<StartReport, AuthError> {
        #[cfg(feature = "crypto")]
        let keys_loaded = self.keys.load().await?;
        #[cfg(not(feature = "crypto"))]
        let keys_loaded = 0;
        let revocations_loaded = self.revocation.load().await?;
        if self.config.authz.mode.uses_permissions() || self.load_catalog {
            self.permissions.reload_catalog().await?;
        }
        let mut extensions = Vec::new();
        for ext in &self.extensions {
            extensions.extend(ext.start().await?);
        }
        // After the extensions started, so e.g. cluster peers receive the
        // key event too.
        #[cfg(feature = "crypto")]
        if let Some(key) = self.own_verifying_key {
            self.keys.publish_verifying_key(key).await?;
        }
        Ok(StartReport {
            revocations_loaded,
            keys_loaded,
            extensions,
        })
    }

    /// Call periodically (with a cluster: every heartbeat): enforce
    /// revocations whose tokens were presented, drop expired denylist
    /// entries, and tick the extensions.
    pub async fn tick(&self) -> Result<TickReport, AuthError> {
        // A fenced instance enforces nothing; it only reports.
        let enforced = if self.is_fenced() {
            0
        } else {
            self.revocation.enforce_pending().await?
        };
        let pruned = self.denylist().prune(self.clock.now());
        let mut extensions = Vec::new();
        for ext in &self.extensions {
            extensions.extend(ext.tick().await?);
        }
        Ok(TickReport {
            enforced,
            pruned,
            extensions,
        })
    }

    /// Call on graceful shutdown: stop the extensions (e.g. leave the
    /// cluster), last registered first.
    pub async fn shutdown(&self) -> Result<(), AuthError> {
        for ext in self.extensions.iter().rev() {
            ext.shutdown().await?;
        }
        Ok(())
    }
}

/// Builds a [`ZAuth`] from the required [`Repositories`] plus the
/// optional parts: the permission repository (permission modes), the
/// extensions, and replacements for the default components.
pub struct ZAuthBuilder {
    config: AuthConfig,
    repos: Repositories,
    extensions: Vec<Arc<dyn Extension>>,
    permissions: Option<Arc<dyn PermissionRepository>>,
    permission_codec: Option<Arc<dyn PermissionCodec>>,
    password_hasher: Option<Arc<dyn PasswordHasher>>,
    access_issuer: Option<Arc<dyn AccessTokenIssuer>>,
    access_decoder: Option<Arc<dyn AccessTokenDecoder>>,
    refresh_codec: Option<Arc<dyn RefreshTokenCodec>>,
    denylist: Option<Arc<Denylist>>,
    clock: Option<Arc<dyn Clock>>,
}

impl ZAuthBuilder {
    pub fn new(config: AuthConfig, repos: Repositories) -> Self {
        Self {
            config,
            repos,
            extensions: Vec::new(),
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

    /// Plug in an optional component (e.g. a cluster from z-auth-cluster).
    /// May be called more than once; extensions are wired and driven in
    /// registration order.
    pub fn extension(mut self, extension: Arc<dyn Extension>) -> Self {
        self.extensions.push(extension);
        self
    }
    /// Required when `AUTH_AUTHZ_MODE` is `permissions` or `combined`
    /// (unless an extension supplies the permission service).
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
    /// a key or a secret is missing, or an extension refuses the setup.
    pub fn build(self) -> Result<ZAuth, AuthError> {
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

        // Phase 1: subscriptions and the fence, before any service exists.
        let mut configure = ConfigureContext {
            config: &self.config,
            node_id,
            clock: &clock,
            subscribers: Vec::new(),
            fence: None,
            provides_permissions: false,
        };
        for ext in &self.extensions {
            ext.configure(&mut configure)?;
        }
        let ConfigureContext {
            mut subscribers,
            fence,
            provides_permissions,
            ..
        } = configure;
        // Events reach every subscriber, nowhere without one.
        let events: Arc<dyn EventPublisher> = match subscribers.len() {
            0 => Arc::new(NoopPublisher),
            1 => subscribers.remove(0),
            _ => Arc::new(FanoutPublisher::new(subscribers)),
        };

        let mode = self.config.authz.mode;
        if mode.uses_permissions() && self.permissions.is_none() && !provides_permissions {
            return Err(AuthError::Config(format!(
                "missing adapter: permissions (required by authorization mode {mode:?})"
            )));
        }

        let verifier = TokenVerifier::new(decoder.clone(), denylist.clone(), clock.clone());
        let verifier = Arc::new(match &fence {
            Some(fence) => verifier.with_fence(fence.clone()),
            None => verifier,
        });
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

        let repos = self.repos;
        let entry_ttl: Duration = self.config.jwt.access_token_ttl + self.config.jwt.leeway;
        let revocation: Arc<dyn TokenRevocationService> =
            Arc::new(TokenRevocationServiceImpl::new(
                repos.sessions.clone(),
                repos.revocations.clone(),
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
            self.permissions.clone(),
            catalog.clone(),
            events.clone(),
        ));
        #[cfg(feature = "crypto")]
        let keys: Arc<dyn KeyService> = Arc::new(KeyServiceImpl::new(
            repos.keys.clone(),
            keyring.clone(),
            events.clone(),
            clock.clone(),
            node_id,
        ));
        let accounts: Arc<dyn RefreshAccountSource> = Arc::new(StoreAccountSource::new(
            repos.users.clone(),
            authz_claims.clone(),
        ));

        let core = CoreHandles {
            config: self.config.clone(),
            node_id,
            clock: clock.clone(),
            entry_ttl,
            denylist,
            keyring: keyring.clone(),
            catalog: catalog.clone(),
            decoder: decoder.clone(),
            verifier: verifier.clone(),
            repositories: repos.clone(),
            permission_repository: self.permissions,
            revocation: revocation.clone(),
        };

        // Phase 2: the shared state exists; swap sources, install the gate.
        let mut assemble = AssembleContext {
            core: &core,
            permissions,
            accounts,
            gate: None,
            load_catalog: false,
        };
        for ext in &self.extensions {
            ext.assemble(&mut assemble)?;
        }
        let AssembleContext {
            permissions,
            accounts,
            gate,
            load_catalog,
            ..
        } = assemble;

        let authentication = AuthenticationServiceImpl::new(
            repos.users.clone(),
            accounts.clone(),
            repos.sessions.clone(),
            revocation.clone(),
            authz_claims,
            hasher.clone(),
            issuer,
            decoder,
            refresh_codec,
            verifier.clone(),
            keyring.clone(),
            clock.clone(),
            self.config.clone(),
        );
        let authentication = match gate {
            Some(gate) => authentication.with_gate(gate),
            None => authentication,
        };
        let users: Arc<dyn UserService> = Arc::new(UserServiceImpl::new(
            repos.users.clone(),
            hasher,
            revocation.clone(),
            self.config.password.clone(),
        ));
        let roles: Arc<dyn RoleService> = Arc::new(RoleServiceImpl::new(
            repos.roles.clone(),
            repos.user_roles.clone(),
            mode,
        ));

        // Phase 3: wrap or replace the public services.
        let mut decorate = DecorateContext {
            core: &core,
            accounts: &accounts,
            users,
            roles,
            permissions,
            authentication: Arc::new(authentication),
            revocation: revocation.clone(),
        };
        for ext in &self.extensions {
            ext.decorate(&mut decorate)?;
        }
        let DecorateContext {
            users,
            roles,
            permissions,
            authentication,
            revocation,
            ..
        } = decorate;

        Ok(ZAuth {
            users,
            roles,
            permissions,
            authorizer: Arc::new(AuthorizerImpl::new(catalog, codec)),
            authentication,
            revocation,
            verifier,
            node_id,
            clock,
            keyring,
            own_verifying_key,
            #[cfg(feature = "crypto")]
            keys,
            extensions: self.extensions,
            fence,
            load_catalog,
            config: self.config,
        })
    }
}

/// Feature-dependent defaults.  Without the feature, the component must be
/// supplied explicitly.
mod defaults {
    use super::*;

    /// An issuer plus its verifying key, when the format exposes one.
    pub type IssuerWithKey = (Arc<dyn AccessTokenIssuer>, Option<[u8; 32]>);

    #[cfg(feature = "argon2")]
    pub fn hasher() -> Result<Arc<dyn PasswordHasher>, AuthError> {
        Ok(Arc::new(crate::identity::credentials::Argon2Hasher))
    }
    #[cfg(not(feature = "argon2"))]
    pub fn hasher() -> Result<Arc<dyn PasswordHasher>, AuthError> {
        Err(missing("password_hasher", "argon2"))
    }

    /// The built-in issuer and its verifying key.
    #[cfg(feature = "crypto")]
    pub fn issuer(config: &AuthConfig) -> Result<IssuerWithKey, AuthError> {
        let issuer = crate::security::token::jwt::Ed25519Issuer::from_config(&config.jwt)?;
        let key = issuer.verifying_key();
        Ok((Arc::new(issuer), Some(key)))
    }
    /// Configured verifying keys plus this instance's own key.
    #[cfg(feature = "crypto")]
    pub fn keyring(config: &AuthConfig, own: Option<[u8; 32]>) -> Result<KeyRing, AuthError> {
        let mut keys = crate::security::token::jwt::configured_verifying_keys(&config.jwt);
        keys.extend(own);
        crate::security::token::jwt::keyring_from_keys(&keys)
    }
    #[cfg(feature = "crypto")]
    pub fn decoder(
        config: &AuthConfig,
        keyring: Arc<KeyRing>,
    ) -> Result<Arc<dyn AccessTokenDecoder>, AuthError> {
        Ok(Arc::new(
            crate::security::token::jwt::Ed25519Decoder::with_keyring(
                keyring,
                config.jwt.issuer.clone(),
                config.jwt.leeway,
            ),
        ))
    }
    #[cfg(feature = "crypto")]
    pub fn refresh_codec(config: &AuthConfig) -> Result<Arc<dyn RefreshTokenCodec>, AuthError> {
        Ok(Arc::new(
            crate::security::token::refresh::HmacRefreshCodec::from_config(&config.session)?,
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
