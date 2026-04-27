/// Session domain models.
///
/// Contains **only** plain data structures.
/// - Persistence logic → [`crate::storage::postgres::session_repo`]
/// - Business logic    → [`crate::auth::service`]

/// A fully hydrated session row as returned from the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub access_token: String,
    pub access_created_at: chrono::DateTime<chrono::Utc>,
    pub access_expires_at: chrono::DateTime<chrono::Utc>,
    pub refresh_token: String,
    pub refresh_created_at: chrono::DateTime<chrono::Utc>,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
}

/// Ready-to-insert session data, produced by the auth service.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub user_id: uuid::Uuid,
    pub access_token: String,
    pub access_expires_at: chrono::DateTime<chrono::Utc>,
    pub refresh_token: String,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
}
