/// SQL query constants for the `users` table.
///
/// All queries use `$N` positional parameters — values are always passed
/// separately and never interpolated into the query string.

pub const INSERT_USER: &str = r#"
    INSERT INTO users (email, password_hash, jwt_secret, username, first_name, last_name)
    VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING
        id, email, password_hash, jwt_secret, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
"#;

pub const FIND_USER_BY_ID: &str = r#"
    SELECT
        id, email, password_hash, jwt_secret, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM users
    WHERE id = $1
"#;

pub const FIND_USER_BY_EMAIL: &str = r#"
    SELECT
        id, email, password_hash, jwt_secret, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM users
    WHERE email = $1
"#;

pub const FIND_USER_BY_USERNAME: &str = r#"
    SELECT
        id, email, password_hash, jwt_secret, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM users
    WHERE username = $1
"#;

pub const EXISTS_BY_EMAIL: &str = r#"
    SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)
"#;

pub const EXISTS_BY_USERNAME: &str = r#"
    SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)
"#;

pub const DELETE_USER: &str = r#"
    DELETE FROM users WHERE id = $1
"#;

pub const ACTIVATE_USER: &str = r#"
    UPDATE users SET is_active = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1
"#;

pub const DEACTIVATE_USER: &str = r#"
    UPDATE users SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE id = $1
"#;

pub const GET_IS_ACTIVE: &str = r#"
    SELECT is_active FROM users WHERE id = $1
"#;

pub const GET_IS_VERIFIED: &str = r#"
    SELECT is_verified FROM users WHERE id = $1
"#;

pub const UPDATE_USER: &str = r#"
    UPDATE users
    SET email = $1,
        password_hash = $2,
        username = $3,
        first_name = $4,
        last_name = $5,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = $6
    RETURNING
        id, email, password_hash, jwt_secret, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
"#;
