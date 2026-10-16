//! External identities and flow states (feature `external-identity`):
//! [`PgExternalIdentityRepository`] and [`PgFlowStateRepository`].  Their
//! tables are created by [`EXTERNAL_MIGRATOR`](crate::EXTERNAL_MIGRATOR).

mod external_queries;
mod external_repository;

pub use external_repository::{PgExternalIdentityRepository, PgFlowStateRepository};
