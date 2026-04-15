use crate::{
    interfaces::db::{role_repo::RoleRepo, user_repo::UserRepo},
    model::config::{DatabaseBackend, DatabaseConfig},
    storage::postgres::pg_pool::{self, PgRoleRepo, PgUserRepo, PgUserRoleRepo},
    utils::errors::AuthError,
};
use std::sync::Arc;

pub async fn build_user_repo(cfg: &DatabaseConfig) -> Result<Arc<dyn UserRepo>, AuthError> {
    match cfg.backend {
        DatabaseBackend::Postgres => {
            let pool = pg_pool::build_pool(cfg)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
            Ok(Arc::new(PgUserRepo::new(pool)))
        }
        DatabaseBackend::MySQL => todo!(),
        DatabaseBackend::Mongo => todo!(),
    }
}

pub async fn build_role_repo(cfg: &DatabaseConfig) -> Result<Arc<dyn RoleRepo>, AuthError> {
    match cfg.backend {
        DatabaseBackend::Postgres => {
            let pool = pg_pool::build_pool(cfg)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
            Ok(Arc::new(PgRoleRepo::new(pool)))
        }
        DatabaseBackend::MySQL => todo!(),
        DatabaseBackend::Mongo => todo!(),
    }
}

pub async fn build_user_role_repo(
    cfg: &DatabaseConfig,
) -> Result<Arc<dyn crate::interfaces::db::user_role_repo::UserRoleRepo>, AuthError> {
    match cfg.backend {
        DatabaseBackend::Postgres => {
            let pool = pg_pool::build_pool(cfg)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
            Ok(Arc::new(PgUserRoleRepo::new(pool)))
        }
        DatabaseBackend::MySQL => todo!(),
        DatabaseBackend::Mongo => todo!(),
    }
}
