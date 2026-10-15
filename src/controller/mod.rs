//! Entry points: the [`facade`] ([`ZAuth`](facade::ZAuth)), the
//! [`extension`] port for optional components, the framework-agnostic
//! [`api`] endpoint contracts and the [`prelude`].

pub mod api;
pub mod extension;
pub mod facade;
pub mod prelude;
pub mod repositories;
