//! Private row types — the only place sqlx's `FromRow` meets the domain.
//!
//! Domain models in z-auth carry no persistence derives; each row struct
//! here maps 1-to-1 to a query's columns and converts into its domain type.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use z_auth::AuthError;
use z_auth::identity::access::{Role, UserRole};
use z_auth::identity::user::{User, UserWithRoles};
use z_auth::security::authorization::{
    Permission, PermissionGrant, PermissionKind, PermissionOption,
};
use z_auth::security::session::{RefreshSnapshot, Session, SessionGeneration};
use z_auth::security::token::{Revocation, RevocationScope, VerifyingKeyRecord};

use crate::codes::from_db_generation;
use crate::enums::{
    PgKeyStatus, PgPermissionKind, PgRevocationReason, PgRevocationScope, PgRevocationStatus,
    PgSessionStatus,
};

#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    id: Uuid,
    email: String,
    password_hash: Option<String>,
    username: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    avatar_url: Option<String>,
    is_active: bool,
    is_verified: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRow> for User {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            password_hash: r.password_hash,
            username: r.username,
            first_name: r.first_name,
            last_name: r.last_name,
            avatar_url: r.avatar_url,
            is_active: r.is_active,
            is_verified: r.is_verified,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// One row of an `identity_users LEFT JOIN identity_role_assignments LEFT JOIN identity_roles` query.
#[derive(sqlx::FromRow)]
pub(crate) struct UserWithRoleRow {
    #[sqlx(flatten)]
    user: UserRow,
    role_id: Option<Uuid>,
    role_code: Option<String>,
    role_name: Option<String>,
    role_description: Option<String>,
    role_created_at: Option<DateTime<Utc>>,
}

/// Fold the joined rows of a single user into a [`UserWithRoles`].
pub(crate) fn fold_user_with_roles(rows: Vec<UserWithRoleRow>) -> Option<UserWithRoles> {
    let mut user = None;
    let mut roles = Vec::new();

    for row in rows {
        // LEFT JOIN: role columns are NULL when the user has no active roles.
        if let (Some(id), Some(code), Some(name), Some(created_at)) = (
            row.role_id,
            row.role_code,
            row.role_name,
            row.role_created_at,
        ) {
            roles.push(Role {
                id,
                code,
                name,
                description: row.role_description,
                created_at,
            });
        }
        user.get_or_insert(row.user);
    }

    user.map(|u| UserWithRoles {
        user: u.into(),
        roles,
    })
}

#[derive(sqlx::FromRow)]
pub(crate) struct RoleRow {
    id: Uuid,
    code: String,
    name: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<RoleRow> for Role {
    fn from(r: RoleRow) -> Self {
        Self {
            id: r.id,
            code: r.code,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct UserRoleRow {
    id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    assigned_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<UserRoleRow> for UserRole {
    fn from(r: UserRoleRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            role_id: r.role_id,
            assigned_at: r.assigned_at,
            revoked_at: r.revoked_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    secret: Vec<u8>,
    status: PgSessionStatus,
    end_reason: Option<PgRevocationReason>,
    created_ip: IpAddr,
    user_agent: Option<String>,
    current_generation: i32,
    created_at: DateTime<Utc>,
    idle_expires_at: DateTime<Utc>,
    absolute_expires_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
}

impl TryFrom<SessionRow> for Session {
    type Error = AuthError;

    fn try_from(r: SessionRow) -> Result<Self, AuthError> {
        Ok(Self {
            id: r.id,
            user_id: r.user_id,
            secret: r.secret,
            status: r.status.into(),
            end_reason: r.end_reason.map(Into::into),
            created_ip: r.created_ip,
            user_agent: r.user_agent,
            current_generation: from_db_generation(r.current_generation)?,
            created_at: r.created_at,
            idle_expires_at: r.idle_expires_at,
            absolute_expires_at: r.absolute_expires_at,
            ended_at: r.ended_at,
        })
    }
}

/// A `security_session_generations` row; its `id` is the access token's `jti`.
#[derive(sqlx::FromRow)]
pub(crate) struct GenerationRow {
    id: Uuid,
    session_id: Uuid,
    generation: i32,
    issued_ip: IpAddr,
    issued_at: DateTime<Utc>,
    access_expires_at: DateTime<Utc>,
    superseded_at: Option<DateTime<Utc>>,
    parent_jti: Option<Uuid>,
    issued_user_agent: Option<String>,
    fingerprint_hash: Option<Vec<u8>>,
    aliases: Vec<Uuid>,
}

pub(crate) fn fingerprint_from_db(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, AuthError> {
    bytes
        .map(|b| {
            <[u8; 32]>::try_from(b.as_slice())
                .map_err(|_| AuthError::Storage("fingerprint_hash must be 32 bytes".into()))
        })
        .transpose()
}

impl TryFrom<GenerationRow> for SessionGeneration {
    type Error = AuthError;

    fn try_from(r: GenerationRow) -> Result<Self, AuthError> {
        Ok(Self {
            session_id: r.session_id,
            generation: from_db_generation(r.generation)?,
            access_jti: r.id,
            issued_ip: r.issued_ip,
            issued_at: r.issued_at,
            access_expires_at: r.access_expires_at,
            superseded_at: r.superseded_at,
            parent_jti: r.parent_jti,
            issued_user_agent: r.issued_user_agent,
            fingerprint_hash: fingerprint_from_db(r.fingerprint_hash)?,
            aliases: r.aliases,
        })
    }
}

/// One row of `LOAD_FOR_REFRESH`: the session, `now()`, and the presented
/// (`p_*`) and current (`c_*`) generations from two LEFT JOINs.
#[derive(sqlx::FromRow)]
pub(crate) struct RefreshRow {
    #[sqlx(flatten)]
    session: SessionRow,
    db_now: DateTime<Utc>,
    p_id: Option<Uuid>,
    p_generation: Option<i32>,
    p_issued_ip: Option<IpAddr>,
    p_issued_at: Option<DateTime<Utc>>,
    p_access_expires_at: Option<DateTime<Utc>>,
    p_superseded_at: Option<DateTime<Utc>>,
    p_parent_jti: Option<Uuid>,
    p_issued_user_agent: Option<String>,
    p_fingerprint_hash: Option<Vec<u8>>,
    p_aliases: Vec<Uuid>,
    c_id: Option<Uuid>,
    c_generation: Option<i32>,
    c_issued_ip: Option<IpAddr>,
    c_issued_at: Option<DateTime<Utc>>,
    c_access_expires_at: Option<DateTime<Utc>>,
    c_superseded_at: Option<DateTime<Utc>>,
    c_parent_jti: Option<Uuid>,
    c_issued_user_agent: Option<String>,
    c_fingerprint_hash: Option<Vec<u8>>,
    c_aliases: Vec<Uuid>,
}

/// The columns of one LEFT-JOINed generation.
struct Joined {
    id: Option<Uuid>,
    generation: Option<i32>,
    issued_ip: Option<IpAddr>,
    issued_at: Option<DateTime<Utc>>,
    access_expires_at: Option<DateTime<Utc>>,
    superseded_at: Option<DateTime<Utc>>,
    parent_jti: Option<Uuid>,
    issued_user_agent: Option<String>,
    fingerprint_hash: Option<Vec<u8>>,
    aliases: Vec<Uuid>,
}

/// Assemble a LEFT-JOINed generation; `None` when the join found no row.
fn joined_generation(session_id: Uuid, j: Joined) -> Result<Option<SessionGeneration>, AuthError> {
    let (Some(id), Some(generation), Some(issued_ip), Some(issued_at), Some(access_expires_at)) = (
        j.id,
        j.generation,
        j.issued_ip,
        j.issued_at,
        j.access_expires_at,
    ) else {
        return Ok(None);
    };
    GenerationRow {
        id,
        session_id,
        generation,
        issued_ip,
        issued_at,
        access_expires_at,
        superseded_at: j.superseded_at,
        parent_jti: j.parent_jti,
        issued_user_agent: j.issued_user_agent,
        fingerprint_hash: j.fingerprint_hash,
        aliases: j.aliases,
    }
    .try_into()
    .map(Some)
}

impl TryFrom<RefreshRow> for RefreshSnapshot {
    type Error = AuthError;

    fn try_from(r: RefreshRow) -> Result<Self, AuthError> {
        let session: Session = r.session.try_into()?;
        Ok(Self {
            presented: joined_generation(
                session.id,
                Joined {
                    id: r.p_id,
                    generation: r.p_generation,
                    issued_ip: r.p_issued_ip,
                    issued_at: r.p_issued_at,
                    access_expires_at: r.p_access_expires_at,
                    superseded_at: r.p_superseded_at,
                    parent_jti: r.p_parent_jti,
                    issued_user_agent: r.p_issued_user_agent,
                    fingerprint_hash: r.p_fingerprint_hash,
                    aliases: r.p_aliases,
                },
            )?,
            current: joined_generation(
                session.id,
                Joined {
                    id: r.c_id,
                    generation: r.c_generation,
                    issued_ip: r.c_issued_ip,
                    issued_at: r.c_issued_at,
                    access_expires_at: r.c_access_expires_at,
                    superseded_at: r.c_superseded_at,
                    parent_jti: r.c_parent_jti,
                    issued_user_agent: r.c_issued_user_agent,
                    fingerprint_hash: r.c_fingerprint_hash,
                    aliases: r.c_aliases,
                },
            )?,
            session,
            now: r.db_now,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct RevocationRow {
    id: Uuid,
    scope: PgRevocationScope,
    subject: Uuid,
    reason: PgRevocationReason,
    status: PgRevocationStatus,
    origin_node: Option<Uuid>,
    revoked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    enforced_at: Option<DateTime<Utc>>,
    enforced_by: Option<Uuid>,
}

impl From<RevocationRow> for Revocation {
    fn from(r: RevocationRow) -> Self {
        Self {
            id: r.id,
            scope: match r.scope {
                PgRevocationScope::Session => RevocationScope::Session(r.subject),
                PgRevocationScope::User => RevocationScope::User(r.subject),
                PgRevocationScope::Token => RevocationScope::Token(r.subject),
            },
            reason: r.reason.into(),
            status: r.status.into(),
            // The column is nullable: rows inserted by plain SQL may have no origin.
            origin_node: r.origin_node.unwrap_or_default(),
            revoked_at: r.revoked_at,
            expires_at: r.expires_at,
            enforced_at: r.enforced_at,
            enforced_by: r.enforced_by,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct KeyRow {
    kid: String,
    public_key: Vec<u8>,
    status: PgKeyStatus,
    published_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<KeyRow> for VerifyingKeyRecord {
    type Error = AuthError;

    fn try_from(r: KeyRow) -> Result<Self, AuthError> {
        Ok(Self {
            kid: r.kid,
            public_key: r
                .public_key
                .try_into()
                .map_err(|_| AuthError::Storage("verifying key is not 32 bytes".into()))?,
            status: r.status.into(),
            published_by: r.published_by,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        })
    }
}

// ── Permissions ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub(crate) struct PermissionRow {
    id: Uuid,
    code: String,
    kind: PgPermissionKind,
    description: Option<String>,
    position: Option<i32>,
    max_length: Option<i32>,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct OptionRow {
    id: Uuid,
    permission_id: Uuid,
    code: String,
    position: i32,
}

#[derive(sqlx::FromRow)]
pub(crate) struct GrantRow {
    position: i32,
    text_value: Option<String>,
}

fn position(p: i32) -> Result<u32, AuthError> {
    u32::try_from(p).map_err(|_| AuthError::Storage("negative permission position".into()))
}

impl PermissionRow {
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }

    /// Combine with its options (any order) into a domain [`Permission`].
    pub(crate) fn assemble(self, options: &[OptionRow]) -> Result<Permission, AuthError> {
        let kind = match self.kind {
            PgPermissionKind::Bool => PermissionKind::Bool,
            PgPermissionKind::Single => PermissionKind::Single,
            PgPermissionKind::Multi => PermissionKind::Multi,
            PgPermissionKind::Text => PermissionKind::Text {
                max_length: self
                    .max_length
                    .and_then(|m| u32::try_from(m).ok())
                    .ok_or_else(|| {
                        AuthError::Storage("text permission without max_length".into())
                    })?,
            },
        };
        let mut opts = options
            .iter()
            .filter(|o| o.permission_id == self.id)
            .map(|o| {
                Ok(PermissionOption {
                    id: o.id,
                    code: o.code.clone(),
                    position: position(o.position)?,
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        opts.sort_by_key(|o| o.position);
        Ok(Permission {
            id: self.id,
            code: self.code,
            kind,
            description: self.description,
            position: self.position.map(position).transpose()?,
            options: opts,
            created_at: self.created_at,
        })
    }
}

impl TryFrom<GrantRow> for PermissionGrant {
    type Error = AuthError;

    fn try_from(r: GrantRow) -> Result<Self, AuthError> {
        Ok(Self {
            position: position(r.position)?,
            text: r.text_value,
        })
    }
}
