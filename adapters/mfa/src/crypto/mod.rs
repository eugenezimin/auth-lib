//! The cryptography behind second factors: [`totp`] (RFC 6238 / 4226),
//! [`base32`], one-time [`codes`] and challenge tokens, and the [`sealer`]
//! that encrypts stored secrets.

pub mod base32;
pub mod codes;
pub mod sealer;
pub mod totp;

pub use sealer::SecretSealer;
#[cfg(feature = "aead")]
pub use sealer::XChaChaSealer;
