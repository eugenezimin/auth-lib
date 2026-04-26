pub(crate) mod db_factory;
pub(crate) mod postgres;
pub(crate) mod queries;

pub(crate) enum DbPool {
    Postgres(sqlx::PgPool),
    MySql(sqlx::MySqlPool),
    // Mongo(mongodb::Client),
}
