//! z-auth-mfa configuration, separate from z-auth's own `AuthConfig`:
//! [`model`] (data) and [`loaders`] (environment / direct, validation).

pub mod loaders;
pub mod model;

pub use loaders::{MfaConfigLoader, MfaDirectLoader, MfaEnvLoader};
pub use model::{
    ChallengeConfig, CodeConfig, Enforcement, LockoutConfig, MfaKeys, MfaSettings, RawMfaConfig,
    RecoveryConfig, TotpConfig, Unenrolled,
};
