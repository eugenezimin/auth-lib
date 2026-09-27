//! Private row types — the only place sqlx's `FromRow` meets the domain.
//!
//! Domain models in auth-lib carry no persistence derives; each row struct
//! here maps 1-to-1 to a query's columns and converts into its domain type.

use std::net::IpAddr;

use auth_lib::AuthError;
use auth_lib::access::{Role, UserRole};
use auth_lib::authentication::{RefreshSnapshot, Session, SessionGeneration};
use auth_lib::token::{Revocation, RevocationScope};
use auth_lib::user::{User, UserWithRoles};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::codes::from_db_generation;
use crate::enums::{PgRevocationReason, PgRevocationScope, PgSessionStatus};

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

/// One row of a `users LEFT JOIN users_roles LEFT JOIN roles` query.
#[derive(sqlx::FromRow)]
pub(crate) struct UserWithRoleRow {
    #[sqlx(flatten)]
    user: UserRow,
    role_id: Option<Uuid>,
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
        if let (Some(id), Some(name), Some(created_at)) =
            (row.role_id, row.role_name, row.role_created_at)
        {
            roles.push(Role {
                id,
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
    name: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<RoleRow> for Role {
    fn from(r: RoleRow) -> Self {
        Self {
            id: r.id,
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

/// A `session_generations` row; its `id` is the access token's `jti`.
#[derive(sqlx::FromRow)]
pub(crate) struct GenerationRow {
    id: Uuid,
    session_id: Uuid,
    generation: i32,
    issued_ip: IpAddr,
    issued_at: DateTime<Utc>,
    access_expires_at: DateTime<Utc>,
    superseded_at: Option<DateTime<Utc>>,
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
    c_id: Option<Uuid>,
    c_generation: Option<i32>,
    c_issued_ip: Option<IpAddr>,
    c_issued_at: Option<DateTime<Utc>>,
    c_access_expires_at: Option<DateTime<Utc>>,
    c_superseded_at: Option<DateTime<Utc>>,
}

/// Assemble a LEFT-JOINed generation; `None` when the join found no row.
fn joined_generation(
    session_id: Uuid,
    id: Option<Uuid>,
    generation: Option<i32>,
    issued_ip: Option<IpAddr>,
    issued_at: Option<DateTime<Utc>>,
    access_expires_at: Option<DateTime<Utc>>,
    superseded_at: Option<DateTime<Utc>>,
) -> Result<Option<SessionGeneration>, AuthError> {
    let (Some(id), Some(generation), Some(issued_ip), Some(issued_at), Some(access_expires_at)) =
        (id, generation, issued_ip, issued_at, access_expires_at)
    else {
        return Ok(None);
    };
    GenerationRow {
        id,
        session_id,
        generation,
        issued_ip,
        issued_at,
        access_expires_at,
        superseded_at,
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
                r.p_id,
                r.p_generation,
                r.p_issued_ip,
                r.p_issued_at,
                r.p_access_expires_at,
                r.p_superseded_at,
            )?,
            current: joined_generation(
                session.id,
                r.c_id,
                r.c_generation,
                r.c_issued_ip,
                r.c_issued_at,
                r.c_access_expires_at,
                r.c_superseded_at,
            )?,
            session,
            now: r.db_now,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct RevocationRow {
    scope: PgRevocationScope,
    subject: Uuid,
    reason: PgRevocationReason,
    revoked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<RevocationRow> for Revocation {
    fn from(r: RevocationRow) -> Self {
        Self {
            scope: match r.scope {
                PgRevocationScope::Session => RevocationScope::Session(r.subject),
                PgRevocationScope::User => RevocationScope::User(r.subject),
            },
            reason: r.reason.into(),
            revoked_at: r.revoked_at,
            expires_at: r.expires_at,
        }
    }
}
