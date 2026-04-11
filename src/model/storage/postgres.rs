/// Postgres-backed user repository.
///
/// Construct with a shared [`Pool`] and pass it (behind an `Arc`) to the
/// service layer:
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use auth_lib::storage::user_repo::PgUserRepo;
///
///
/// let repo = Arc::new(PgUserRepo::new(pool.clone()));
/// ```
use deadpool_postgres::Pool;

pub struct PgUserRepo {
    pub pg_pool: Pool,
}
