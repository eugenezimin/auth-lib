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

pub const FIND_USER_BY_EMAIL: &str = r#"
    SELECT
        id, email, password_hash, jwt_secret, username,
        first_name, last_name, avatar_url,
        is_active, is_verified, created_at, updated_at
    FROM users
    WHERE email = $1
"#;

pub const EXISTS_BY_EMAIL: &str = r#"
    SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)
"#;

pub const EXISTS_BY_USERNAME: &str = r#"
    SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)
"#;
