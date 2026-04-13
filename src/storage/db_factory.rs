use crate::interfaces::db::user_repo::UserRepo;
use crate::model::config::{DatabaseBackend, DatabaseConfig};
use crate::storage::postgres;
use crate::utils::errors::AuthError;
use std::sync::Arc;

pub async fn build_user_repo(cfg: &DatabaseConfig) -> Result<Arc<dyn UserRepo>, AuthError> {
    match cfg.backend {
        DatabaseBackend::Postgres => {
            let pool = postgres::pg_pool::build_pool(cfg)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
            Ok(Arc::new(postgres::pg_pool::PgUserRepo::new(pool)))
        }
        DatabaseBackend::MySQL => todo!(),
        DatabaseBackend::Mongo => todo!(),
    }
}
