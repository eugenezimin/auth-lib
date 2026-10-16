//! [`Mfa`] — z-auth-mfa as a z-auth [`Extension`].

use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use z_auth::AuthError;
use z_auth::controller::extension::{
    AssembleContext, ConfigureContext, Extension, ExtensionReport,
};

use crate::config::{Enforcement, MfaSettings};
use crate::constants::ENV_MFA_METHODS;
use crate::crypto::sealer::SecretSealer;
use crate::report::MfaTickReport;
use crate::repository::MfaRepository;
use crate::sender::CodeSender;
use crate::service::MfaService;
use crate::service_impl::MfaServiceImpl;

/// The extension's name in reports and errors.
pub const EXTENSION_NAME: &str = "z-auth-mfa";

/// Two-factor authentication for one [`ZAuth`](z_auth::ZAuth):
///
/// ```rust,ignore
/// let mfa = Arc::new(
///     Mfa::new(MfaEnvLoader.load_settings()?, Arc::new(PgMfaRepository::new(pool.clone())))
///         .with_code_sender(Arc::new(my_mailer)),   // when email / sms are enabled
/// );
/// let auth = ZAuth::builder(config, repos).extension(mfa.clone()).build()?;
/// let enrollment = mfa.service().unwrap();          // the MfaService
/// ```
///
/// At build time it validates its setup and installs the second-factor gate
/// (unless enforcement is `off`); every [`ZAuth::tick`](z_auth::ZAuth::tick)
/// purges expired challenges and enrollments now and then.
pub struct Mfa {
    settings: MfaSettings,
    repo: Arc<dyn MfaRepository>,
    sender: Option<Arc<dyn CodeSender>>,
    sealer: Option<Arc<dyn SecretSealer>>,
    service: OnceLock<Arc<MfaServiceImpl>>,
    next_purge: Mutex<Option<DateTime<Utc>>>,
}

impl Mfa {
    pub fn new(settings: MfaSettings, repo: Arc<dyn MfaRepository>) -> Self {
        Self {
            settings,
            repo,
            sender: None,
            sealer: None,
            service: OnceLock::new(),
            next_purge: Mutex::new(None),
        }
    }

    /// Delivers email / SMS codes.  Required when `AUTH_MFA_METHODS`
    /// includes `email` or `sms`.
    pub fn with_code_sender(mut self, sender: Arc<dyn CodeSender>) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Seals stored secrets (e.g. with a KMS).  Defaults to XChaCha20-Poly1305
    /// under `AUTH_MFA_ENCRYPTION_KEY` (feature `aead`).
    pub fn with_sealer(mut self, sealer: Arc<dyn SecretSealer>) -> Self {
        self.sealer = Some(sealer);
        self
    }

    pub fn settings(&self) -> &MfaSettings {
        &self.settings
    }

    /// Enrollment and factor management.  `None` until the
    /// [`ZAuth`](z_auth::ZAuth) this extension was registered with is
    /// built.
    pub fn service(&self) -> Option<Arc<dyn MfaService>> {
        self.service.get().map(|s| s.clone() as Arc<dyn MfaService>)
    }

    fn sealer(&self) -> Result<Arc<dyn SecretSealer>, AuthError> {
        if let Some(sealer) = &self.sealer {
            return Ok(sealer.clone());
        }
        #[cfg(feature = "aead")]
        {
            let key = self.settings.keys.encryption_key.ok_or_else(|| {
                AuthError::Config(format!(
                    "missing {} (or supply a sealer with Mfa::with_sealer)",
                    crate::constants::ENV_MFA_ENCRYPTION_KEY
                ))
            })?;
            Ok(Arc::new(crate::crypto::XChaChaSealer::new(
                &key,
                &self.settings.keys.previous_encryption_keys,
            )))
        }
        #[cfg(not(feature = "aead"))]
        Err(AuthError::Config(
            "z-auth-mfa needs a sealer: enable the `aead` feature or call Mfa::with_sealer".into(),
        ))
    }
}

#[async_trait]
impl Extension for Mfa {
    fn name(&self) -> &'static str {
        EXTENSION_NAME
    }

    fn configure(&self, _ctx: &mut ConfigureContext<'_>) -> Result<(), AuthError> {
        if self.settings.methods.iter().any(|m| m.is_delivered()) && self.sender.is_none() {
            return Err(AuthError::Config(format!(
                "{ENV_MFA_METHODS} includes email or sms but no CodeSender was given \
                 (Mfa::with_code_sender)"
            )));
        }
        self.sealer().map(|_| ())
    }

    fn assemble(&self, ctx: &mut AssembleContext<'_>) -> Result<(), AuthError> {
        let core = ctx.core();
        let service = Arc::new(MfaServiceImpl::new(
            self.settings.clone(),
            self.repo.clone(),
            core.repositories().users.clone(),
            core.revocation().clone(),
            self.sender.clone(),
            self.sealer()?,
            core.clock().clone(),
            &core.config().jwt.issuer,
        ));
        self.service.set(service.clone()).map_err(|_| {
            AuthError::Config(format!("{EXTENSION_NAME} is already wired into a ZAuth"))
        })?;
        if self.settings.enforcement != Enforcement::Off {
            ctx.set_second_factor_gate(service)?;
        }
        Ok(())
    }

    async fn tick(&self) -> Result<Option<ExtensionReport>, AuthError> {
        let Some(service) = self.service.get() else {
            return Ok(None);
        };
        let now = service.clock.now();
        {
            let mut next = self.next_purge.lock().unwrap_or_else(|e| e.into_inner());
            if next.is_some_and(|t| t > now) {
                return Ok(None);
            }
            *next = Some(now + self.settings.purge_interval);
        }
        let purged = self.repo.purge(self.settings.purge_retention).await?;
        Ok(Some(ExtensionReport::new(
            EXTENSION_NAME,
            MfaTickReport { purged },
        )))
    }
}
