//! Cross-cutting helpers: the library [`error`] type, the [`clock`] port,
//! the serving [`fence`], secure randomness and code [`validation`].

pub mod clock;
pub mod error;
pub mod fence;
pub(crate) mod random;
pub mod validation;
