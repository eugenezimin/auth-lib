//! SQL query constants for the `identity_roles` table.
//!
//! All queries use `$N` positional parameters — values are never interpolated.

pub const INSERT_ROLE: &str = r#"
    INSERT INTO identity_roles (code, name, description)
    VALUES ($1, $2, $3)
    RETURNING id, code, name, description, created_at
"#;

pub const FIND_ROLE_BY_ID: &str = r#"
    SELECT id, code, name, description, created_at
    FROM identity_roles
    WHERE id = $1
"#;

pub const FIND_ROLE_BY_NAME: &str = r#"
    SELECT id, code, name, description, created_at
    FROM identity_roles
    WHERE name = $1
"#;

pub const FIND_ROLE_BY_CODE: &str = r#"
    SELECT id, code, name, description, created_at
    FROM identity_roles
    WHERE code = $1
"#;

pub const LIST_ALL_ROLES: &str = r#"
    SELECT id, code, name, description, created_at
    FROM identity_roles
    ORDER BY name ASC
"#;

/// Partial update — a `NULL` `$1` keeps the name; `$2` says whether to
/// replace the description with `$3` (which may be `NULL`, clearing it).
pub const UPDATE_ROLE: &str = r#"
    UPDATE identity_roles
    SET name        = COALESCE($1, name),
        description = CASE WHEN $2 THEN $3 ELSE description END
    WHERE id = $4
    RETURNING id, code, name, description, created_at
"#;

pub const DELETE_ROLE: &str = r#"
    DELETE FROM identity_roles WHERE id = $1 RETURNING id
"#;

pub const EXISTS_BY_NAME: &str = r#"
    SELECT EXISTS(SELECT 1 FROM identity_roles WHERE name = $1)
"#;
