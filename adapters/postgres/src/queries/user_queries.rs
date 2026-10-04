//! SQL query constants for the `users` table.
//!
//! All queries use `$N` positional parameters — values are always passed
//! separately and never interpolated into the query string.
//!
//! Email and username lookups compare `lower(col) = lower($1)` so they hit
//! the case-insensitive unique indexes `users_email` / `users_username_key`.

pub const INSERT_USER: &str = r#"
    INSERT INTO users (email, password_hash, username, first_name, last_name)
    VALUES ($1, $2, $3, $4, $5)
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
    FROM users
    WHERE id = $1
"#;

pub const FIND_USER_BY_EMAIL: &str = r#"
    SELECT
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM users
    WHERE lower(email) = lower($1)
"#;

pub const FIND_USER_BY_USERNAME: &str = r#"
    SELECT
        id, email, password_hash, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM users
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
    FROM      users u
    LEFT JOIN users_roles ur ON ur.user_id = u.id AND ur.revoked_at IS NULL
    LEFT JOIN roles r        ON r.id = ur.role_id
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
    FROM      users u
    LEFT JOIN users_roles ur ON ur.user_id = u.id AND ur.revoked_at IS NULL
    LEFT JOIN roles r        ON r.id = ur.role_id
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
    FROM      users u
    LEFT JOIN users_roles ur ON ur.user_id = u.id AND ur.revoked_at IS NULL
    LEFT JOIN roles r        ON r.id = ur.role_id
    WHERE     lower(u.username) = lower($1)
"#;

pub const EXISTS_BY_EMAIL: &str = r#"
    SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = lower($1))
"#;

pub const EXISTS_BY_USERNAME: &str = r#"
    SELECT EXISTS(SELECT 1 FROM users WHERE lower(username) = lower($1))
"#;

pub const DELETE_USER: &str = r#"
    DELETE FROM users WHERE id = $1 RETURNING id
"#;

pub const ACTIVATE_USER: &str = r#"
    UPDATE users SET is_active = true, updated_at = now() WHERE id = $1
"#;

pub const DEACTIVATE_USER: &str = r#"
    UPDATE users SET is_active = false, updated_at = now() WHERE id = $1
"#;

pub const GET_IS_ACTIVE: &str = r#"
    SELECT is_active FROM users WHERE id = $1
"#;

pub const GET_IS_VERIFIED: &str = r#"
    SELECT is_verified FROM users WHERE id = $1
"#;

/// Partial update — `NULL` parameters leave the column unchanged.
/// `$2` is an already-hashed password.
pub const UPDATE_USER: &str = r#"
    UPDATE users
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
