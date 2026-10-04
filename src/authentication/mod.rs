//! Authentication context — login sessions, token rotation and the refresh
//! policy.

pub mod model;
pub mod policy;
pub mod repository;
pub mod service;
pub mod service_impl;

pub use model::{
    ClientContext, Credentials, NewSession, RefreshSnapshot, RotateOutcome, Session,
    SessionGeneration, SessionLifetimes, SessionStatus, TokenPair,
};
pub use repository::SessionRepository;
pub use service::AuthenticationService;
pub use service_impl::AuthenticationServiceImpl;
