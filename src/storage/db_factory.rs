use crate::{
    interfaces::db::{role_repo::RoleRepo, user_repo::UserRepo, user_role_repo::UserRoleRepo},
    storage::{
        DbPool,
        postgres::pg_pool::{PgRoleRepo, PgUserRepo, PgUserRoleRepo},
    },
};
use std::sync::Arc;

pub(crate) fn build_user_repo(pool: &DbPool) -> Arc<dyn UserRepo> {
    match pool {
        DbPool::Postgres(pg) => Arc::new(PgUserRepo::new(pg.clone())),
        DbPool::MySql(my) => todo!(),
    }
}

pub(crate) fn build_role_repo(pool: &DbPool) -> Arc<dyn RoleRepo> {
    match pool {
        DbPool::Postgres(pg) => Arc::new(PgRoleRepo::new(pg.clone())),
        DbPool::MySql(my) => todo!(),
    }
}

pub(crate) fn build_user_role_repo(pool: &DbPool) -> Arc<dyn UserRoleRepo> {
    match pool {
        DbPool::Postgres(pg) => Arc::new(PgUserRoleRepo::new(pg.clone())),
        DbPool::MySql(my) => todo!(),
    }
}
