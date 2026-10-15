//! Authentication context — login sessions, token rotation and the refresh
//! policy.

pub mod account;
pub mod gate;
pub mod model;
pub mod policy;
pub mod service;
pub mod service_impl;

pub use account::{RefreshAccount, RefreshAccountSource, StoreAccountSource};
pub use gate::RefreshGate;
pub use model::{ClientContext, Credentials, TokenPair};
pub use service::AuthenticationService;
pub use service_impl::AuthenticationServiceImpl;
