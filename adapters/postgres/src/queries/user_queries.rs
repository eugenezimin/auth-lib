//! SQL query constants for the `identity_users` table.
//!
//! All queries use `$N` positional parameters — values are always passed
//! separately and never interpolated into the query string.
//!
//! Email and username lookups compare `lower(col) = lower($1)` so they hit
//! the case-insensitive unique indexes `users_email` / `users_username_key`.

pub const INSERT_USER: &str = r#"
    INSERT INTO identity_users (email, password_hash, username, first_name, last_name, is_verified)
    VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
"#;

pub const FIND_USER_BY_ID: &str = r#"
    SELECT
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM identity_users
    WHERE id = $1
"#;

pub const FIND_USER_BY_EMAIL: &str = r#"
    SELECT
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM identity_users
    WHERE lower(email) = lower($1)
"#;

pub const FIND_USER_BY_USERNAME: &str = r#"
    SELECT
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM identity_users
    WHERE lower(username) = lower($1)
"#;

pub const FIND_USER_WITH_ROLES_BY_ID: &str = r#"
    SELECT
        u.id, u.email, u.password_hash, u.username,
        u.first_name, u.last_name, u.avatar_url,
        u.is_active, u.is_verified, u.created_at, u.updated_at,
        r.id          AS role_id,
        r.code        AS role_code,
        r.name        AS role_name,
        r.description AS role_description,
        r.created_at  AS role_created_at
    FROM      identity_users u
    LEFT JOIN identity_role_assignments ur ON ur.user_id = u.id AND ur.revoked_at IS NULL
    LEFT JOIN identity_roles r        ON r.id = ur.role_id
    WHERE     u.id = $1
"#;

pub const FIND_USER_WITH_ROLES_BY_EMAIL: &str = r#"
    SELECT
        u.id, u.email, u.password_hash, u.username,
        u.first_name, u.last_name, u.avatar_url,
        u.is_active, u.is_verified, u.created_at, u.updated_at,
        r.id          AS role_id,
        r.code        AS role_code,
        r.name        AS role_name,
        r.description AS role_description,
        r.created_at  AS role_created_at
    FROM      identity_users u
    LEFT JOIN identity_role_assignments ur ON ur.user_id = u.id AND ur.revoked_at IS NULL
    LEFT JOIN identity_roles r        ON r.id = ur.role_id
    WHERE     lower(u.email) = lower($1)
"#;

pub const FIND_USER_WITH_ROLES_BY_USERNAME: &str = r#"
    SELECT
        u.id, u.email, u.password_hash, u.username,
        u.first_name, u.last_name, u.avatar_url,
        u.is_active, u.is_verified, u.created_at, u.updated_at,
        r.id          AS role_id,
        r.code        AS role_code,
        r.name        AS role_name,
        r.description AS role_description,
        r.created_at  AS role_created_at
    FROM      identity_users u
    LEFT JOIN identity_role_assignments ur ON ur.user_id = u.id AND ur.revoked_at IS NULL
    LEFT JOIN identity_roles r        ON r.id = ur.role_id
    WHERE     lower(u.username) = lower($1)
"#;

pub const EXISTS_BY_EMAIL: &str = r#"
    SELECT EXISTS(SELECT 1 FROM identity_users WHERE lower(email) = lower($1))
"#;

pub const EXISTS_BY_USERNAME: &str = r#"
    SELECT EXISTS(SELECT 1 FROM identity_users WHERE lower(username) = lower($1))
"#;

/// One page, newest first.  `$1` (nullable) is a case-insensitive
/// substring of email or username — `strpos`, so `%` / `_` match literally.
pub const LIST_USERS: &str = r#"
    SELECT
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM identity_users
    WHERE $1::text IS NULL
       OR strpos(lower(email), lower($1)) > 0
       OR strpos(lower(COALESCE(username, '')), lower($1)) > 0
    ORDER BY created_at DESC, id DESC
    LIMIT $2 OFFSET $3
"#;

/// Total for [`LIST_USERS`] with the same `$1` filter.
pub const COUNT_USERS: &str = r#"
    SELECT count(*)
    FROM identity_users
    WHERE $1::text IS NULL
       OR strpos(lower(email), lower($1)) > 0
       OR strpos(lower(COALESCE(username, '')), lower($1)) > 0
"#;

pub const DELETE_USER: &str = r#"
    DELETE FROM identity_users WHERE id = $1 RETURNING id
"#;

pub const ACTIVATE_USER: &str = r#"
    UPDATE identity_users SET is_active = true, updated_at = now() WHERE id = $1
"#;

pub const DEACTIVATE_USER: &str = r#"
    UPDATE identity_users SET is_active = false, updated_at = now() WHERE id = $1
"#;

pub const GET_IS_ACTIVE: &str = r#"
    SELECT is_active FROM identity_users WHERE id = $1
"#;

pub const GET_IS_VERIFIED: &str = r#"
    SELECT is_verified FROM identity_users WHERE id = $1
"#;

/// Partial update — `NULL` parameters leave the column unchanged.
/// `$2` is an already-hashed password.
pub const UPDATE_USER: &str = r#"
    UPDATE identity_users
    SET email         = COALESCE($1, email),
        password_hash = COALESCE($2, password_hash),
        username      = COALESCE($3, username),
        first_name    = COALESCE($4, first_name),
        last_name     = COALESCE($5, last_name),
        avatar_url    = COALESCE($6, avatar_url),
        updated_at    = now()
    WHERE id = $7
    RETURNING
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
"#;
