//! Token domain models — access-token claims, refresh-token parts and
//! revocations.
//!
//! Contains **only** plain data structures.
//! - Codec contracts      → [`crate::token::codec`]
//! - Persistence contract → [`crate::token::repository`]
//! - Service contract     → [`crate::token::service`]

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Claims carried by every access token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Claims {
    /// Subject — the user ID.
    pub sub: Uuid,
    /// Session ID.
    pub sid: Uuid,
    /// Token ID — the issuing generation's ID (`access_jti`).
    pub jti: Uuid,
    /// Session generation that issued this token (`gen` on the wire).
    pub generation: u32,
    /// Issuer.
    pub iss: String,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// Authorization data, present unless `AUTH_AUTHZ_MODE=none`.
    pub authz: Option<AuthzClaims>,
}

/// Authorization data carried by an access token (`rol`, `prm`, `pv`).
/// A snapshot taken at login / refresh; the next refresh picks up changes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthzClaims {
    /// Active role codes (`rol`), sorted.
    pub roles: Vec<String>,
    /// Encoded permissions (`prm` + `pv`).
    pub permissions: Option<EncodedPermissions>,
}

/// Permissions in their compact token form — decode them with
/// [`Authorizer::permissions`](crate::authorization::Authorizer::permissions)
/// (backend) or the catalog + `docs/authorization.md` (UI).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncodedPermissions {
    /// Catalog version the bits refer to (`pv`).
    pub catalog_version: u64,
    /// base64url (no padding) bitset of granted positions (`prm.b`).
    pub bits: String,
    /// `text` permission values by position (`prm.t`).
    pub text: BTreeMap<u32, String>,
}

/// Whether [`AccessTokenDecoder::decode`](crate::token::AccessTokenDecoder::decode)
/// enforces `exp`.  The refresh flow and revocation decode expired tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryCheck {
    Enforce,
    Ignore,
}

/// A parsed (not yet verified) refresh token: `v1.<sid>.<gen>.<mac>`.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub session_id: Uuid,
    pub generation: u32,
    pub mac: Vec<u8>,
}

/// What a revocation applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "id", rename_all = "snake_case")
)]
pub enum RevocationScope {
    /// Every token of one session.
    Session(Uuid),
    /// Every token of a user issued at or before `revoked_at`.
    User(Uuid),
}

/// Why a session ended or a revocation was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RevocationReason {
    /// Single-session logout.
    Logout,
    /// Logout from every session of the user.
    LogoutAll,
    /// Oldest session closed to respect `max_sessions_per_user`.
    Evicted,
    /// A superseded refresh token was presented again.
    TokenReuse,
    /// A refresh came from an IP other than the session's creating IP.
    IpMismatch,
    /// Reported as stolen / leaked (e.g. via the revocation API).
    Compromised,
    /// Revoked by an administrator or an external system.
    Administrative,
    /// The user's password was changed; every earlier session is ended.
    PasswordChanged,
    /// The user account was deactivated.
    AccountDisabled,
    /// The user account was deleted.
    AccountDeleted,
    /// A token covered by a pending revocation was presented: the session is
    /// treated as compromised.
    RevokedTokenUsed,
}

/// Where a revocation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RevocationStatus {
    /// Published; tokens it covers may still be in flight.
    Pending,
    /// A covered token was presented and blocked; its session is marked
    /// compromised.  Terminal.
    Enforced,
}

/// A denylist entry, persisted and mirrored in memory on every instance.
/// Timestamps are assigned by the store.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Revocation {
    pub id: Uuid,
    pub scope: RevocationScope,
    pub reason: RevocationReason,
    pub status: RevocationStatus,
    /// The auth-lib instance that issued the revocation.
    pub origin_node: Uuid,
    /// For [`RevocationScope::User`], tokens issued at or before this
    /// instant are revoked.
    pub revoked_at: DateTime<Utc>,
    /// After this instant every token covered by the entry has expired on
    /// its own, so the entry can be dropped.
    pub expires_at: DateTime<Utc>,
    /// Set once a covered token was presented and blocked.
    pub enforced_at: Option<DateTime<Utc>>,
    /// The instance that enforced it.
    pub enforced_by: Option<Uuid>,
}

/// Ready-to-insert revocation.  The store stamps `revoked_at = now` and
/// `expires_at = now + ttl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewRevocation {
    pub scope: RevocationScope,
    pub reason: RevocationReason,
    /// How long the entry must live: access-token TTL + leeway.
    pub ttl: Duration,
    /// This instance's node id.
    pub origin_node: Uuid,
}

/// A token presented while covered by a **pending** revocation — recorded
/// by the denylist during verification, enforced later by
/// [`TokenRevocationService::enforce_pending`](crate::token::TokenRevocationService::enforce_pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnforcementHit {
    pub revocation_id: Uuid,
    /// Session of the presented token — marked compromised.
    pub session_id: Uuid,
}

/// Lifecycle of a published verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum KeyStatus {
    Active,
    /// Tokens signed with the matching signing key are rejected.  Terminal.
    Revoked,
}

/// A public Ed25519 verifying key known to the cluster.  Private keys never
/// leave the instance that holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifyingKeyRecord {
    /// JWT `kid` (see `token::jwt::key_id`).
    pub kid: String,
    pub public_key: [u8; 32],
    pub status: KeyStatus,
    /// Instance that published it; `None` for keys from configuration.
    pub published_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Ready-to-store verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVerifyingKey {
    pub kid: String,
    pub public_key: [u8; 32],
    pub published_by: Uuid,
}

/// Input to [`TokenRevocationService::revoke`](crate::token::TokenRevocationService::revoke).
///
/// Revoking a token ends its whole session.
#[derive(Clone, PartialEq, Eq)]
pub enum RevokeTarget {
    /// A raw access token (may be expired).
    AccessToken(String),
    /// A raw refresh token.
    RefreshToken(String),
    /// A session by ID.
    Session(Uuid),
    /// Every session of a user.
    User(Uuid),
}

// ── Redacting Debug impls ─────────────────────────────────────────────────────

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshToken")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("mac", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for RevokeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken(_) => f.write_str("AccessToken(<redacted>)"),
            Self::RefreshToken(_) => f.write_str("RefreshToken(<redacted>)"),
            Self::Session(id) => f.debug_tuple("Session").field(id).finish(),
            Self::User(id) => f.debug_tuple("User").field(id).finish(),
        }
    }
}
