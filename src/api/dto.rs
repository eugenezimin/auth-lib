//! API data-transfer objects — the wire shapes of the library's endpoints.
//!
//! Contains **only** plain data structures, kept separate from domain models
//! so the wire format can evolve independently.  Conversions live in
//! [`crate::api::mapping`].  Enable the `serde` feature for
//! `Serialize` / `Deserialize` derives.

use crate::token::model::RevocationReason;

// ── Users ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Public view of a user — never contains `password_hash`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserResponse {
    pub id: uuid::Uuid,
    pub email: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Authentication ────────────────────────────────────────────────────────────

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Both tokens are required: the (expired) access token and its refresh token.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RefreshRequest {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenPairResponse {
    pub session_id: uuid::Uuid,
    pub access_token: String,
    pub access_expires_at: chrono::DateTime<chrono::Utc>,
    pub refresh_token: String,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
}

// ── Token revocation ──────────────────────────────────────────────────────────

/// Something to revoke.  Revoking a token ends its whole session.
///
/// JSON (feature `serde`): `{"type": "access_token", "value": "<jwt>"}`,
/// `{"type": "session", "value": "<uuid>"}`, …
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "value", rename_all = "snake_case")
)]
pub enum RevokeTargetDto {
    AccessToken(String),
    RefreshToken(String),
    Session(uuid::Uuid),
    User(uuid::Uuid),
}

/// Body of the endpoint that accepts revoked tokens.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevokeRequest {
    pub targets: Vec<RevokeTargetDto>,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevokeResponse {
    /// Number of sessions ended.  Invalid tokens are skipped.
    pub sessions_ended: u64,
}

// ── Authorization ─────────────────────────────────────────────────────────────

/// The permission catalog, as fetched by UIs to decode tokens' `prm` claim
/// (see `docs/authorization.md`).  Fetch it once; refetch only when a
/// token's `pv` exceeds `version`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionCatalogResponse {
    pub version: u64,
    pub permissions: Vec<PermissionDto>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionDto {
    pub code: String,
    /// `bool` | `single` | `multi` | `text`.
    pub kind: String,
    pub description: Option<String>,
    /// Bit (`bool`) or text-map key (`text`); `None` for `single` / `multi`.
    pub position: Option<u32>,
    /// `text` only.
    pub max_length: Option<u32>,
    /// `single` / `multi` only.
    pub options: Vec<PermissionOptionDto>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionOptionDto {
    pub code: String,
    pub position: u32,
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// JSON-friendly error body; build it from an [`ApiError`](crate::api::ApiError).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("email", &self.email)
            .field("password", &REDACTED)
            .field("username", &self.username)
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("email", &self.email)
            .field("password", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for TokenPairResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPairResponse")
            .field("session_id", &self.session_id)
            .field("access_token", &REDACTED)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &REDACTED)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

impl std::fmt::Debug for RevokeTargetDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken(_) => f.write_str("AccessToken(<redacted>)"),
            Self::RefreshToken(_) => f.write_str("RefreshToken(<redacted>)"),
            Self::Session(id) => f.debug_tuple("Session").field(id).finish(),
            Self::User(id) => f.debug_tuple("User").field(id).finish(),
        }
    }
}
