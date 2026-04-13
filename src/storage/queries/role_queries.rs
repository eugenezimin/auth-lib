/// SQL query constants for the `roles` table.
///
/// All queries use `$N` positional parameters — values are never interpolated.

pub const INSERT_ROLE: &str = r#"
    INSERT INTO roles (name, description)
    VALUES ($1, $2)
    RETURNING id, name, description, created_at
"#;

pub const FIND_ROLE_BY_ID: &str = r#"
    SELECT id, name, description, created_at
    FROM roles
    WHERE id = $1
"#;

pub const FIND_ROLE_BY_NAME: &str = r#"
    SELECT id, name, description, created_at
    FROM roles
    WHERE name = $1
"#;

pub const LIST_ALL_ROLES: &str = r#"
    SELECT id, name, description, created_at
    FROM roles
    ORDER BY name ASC
"#;

pub const DELETE_ROLE: &str = r#"
    DELETE FROM roles WHERE id = $1
"#;

pub const EXISTS_BY_NAME: &str = r#"
    SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)
"#;
