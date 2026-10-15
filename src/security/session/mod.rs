//! Session context — login sessions, their token generations, why they end,
//! and the [`SessionRepository`] port that persists them.  Shared by
//! [`token`](crate::security::token) (revocation) and
//! [`authentication`](crate::security::authentication) (login and refresh).

pub mod model;
pub mod repository;

pub use model::{
    IssueContext, NewSession, RefreshSnapshot, RequestTraits, RevocationReason, RotateOutcome,
    Session, SessionGeneration, SessionLifetimes, SessionStatus,
};
pub use repository::SessionRepository;
