//! Second-factor storage for z-auth-mfa (feature `mfa`): [`PgMfaRepository`].
//! Its tables are created by [`MFA_MIGRATOR`](crate::MFA_MIGRATOR).

mod mfa_queries;
mod mfa_repository;
mod mfa_row;

pub use mfa_repository::PgMfaRepository;
