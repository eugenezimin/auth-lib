//! SQL query constants for the permission catalog and grants.
//!
//! All queries use `$N` positional parameters — values are never interpolated.

/// `$4` = whether the entry takes a position itself (`bool` / `text`).
pub const INSERT_PERMISSION: &str = r#"
    INSERT INTO security_permissions (code, kind, description, position, max_length)
    VALUES ($1, $2, $3, CASE WHEN $4 THEN nextval('security_permission_position_seq') END, $5)
    RETURNING id
"#;

/// The option's position comes from the column default (the shared sequence).
pub const INSERT_OPTION: &str = r#"
    INSERT INTO security_permission_options (permission_id, code) VALUES ($1, $2)
"#;

pub const DELETE_PERMISSION: &str = r#"
    DELETE FROM security_permissions WHERE id = $1
"#;

pub const FIND_PERMISSION_BY_ID: &str = r#"
    SELECT id, code, kind, description, position, max_length, created_at
    FROM security_permissions
    WHERE id = $1
"#;

pub const FIND_PERMISSION_BY_CODE: &str = r#"
    SELECT id, code, kind, description, position, max_length, created_at
    FROM security_permissions
    WHERE code = $1
"#;

pub const LIST_OPTIONS_OF: &str = r#"
    SELECT id, permission_id, code, position
    FROM security_permission_options
    WHERE permission_id = $1
    ORDER BY position
"#;

pub const LIST_PERMISSIONS: &str = r#"
    SELECT id, code, kind, description, position, max_length, created_at
    FROM security_permissions
    ORDER BY code
"#;

pub const LIST_OPTIONS: &str = r#"
    SELECT id, permission_id, code, position
    FROM security_permission_options
    ORDER BY position
"#;

/// Highest position in use — the catalog version (0 when empty).
pub const CATALOG_VERSION: &str = r#"
    SELECT COALESCE(GREATEST((SELECT max(position) FROM security_permissions),
                             (SELECT max(position) FROM security_permission_options)), 0)::bigint
"#;

pub const DELETE_USER_GRANT: &str = r#"
    DELETE FROM security_user_grants WHERE user_id = $1 AND permission_id = $2
"#;

pub const INSERT_USER_GRANT: &str = r#"
    INSERT INTO security_user_grants (user_id, permission_id, option_id, text_value)
    VALUES ($1, $2, $3, $4)
"#;

/// A user's direct grant rows, grouped by permission for folding.
pub const LIST_USER_GRANTS: &str = r#"
    SELECT permission_id, option_id, text_value
    FROM security_user_grants
    WHERE user_id = $1
    ORDER BY permission_id, option_id
"#;

/// A role's grant rows, grouped by permission for folding.
pub const LIST_ROLE_GRANTS: &str = r#"
    SELECT permission_id, option_id, text_value
    FROM security_role_grants
    WHERE role_id = $1
    ORDER BY permission_id, option_id
"#;

pub const DELETE_ROLE_GRANT: &str = r#"
    DELETE FROM security_role_grants WHERE role_id = $1 AND permission_id = $2
"#;

pub const INSERT_ROLE_GRANT: &str = r#"
    INSERT INTO security_role_grants (role_id, permission_id, option_id, text_value)
    VALUES ($1, $2, $3, $4)
"#;

/// A user's effective grants: direct grants (rank 0) plus — when `$2` —
/// grants of the user's active roles (rank 1, ordered by role code).
/// `bool` / `multi` take the union; `single` / `text` take the first source
/// by (rank, role code).  Returns one row per granted position.
pub const EFFECTIVE_GRANTS: &str = r#"
    WITH sources AS (
        SELECT 0 AS rank, ''::text AS role_code, g.permission_id, g.option_id, g.text_value
        FROM security_user_grants g
        WHERE g.user_id = $1
        UNION ALL
        SELECT 1, r.code::text, g.permission_id, g.option_id, g.text_value
        FROM security_role_grants g
        JOIN identity_role_assignments ur ON ur.role_id = g.role_id
                           AND ur.user_id = $1
                           AND ur.revoked_at IS NULL
        JOIN identity_roles r ON r.id = g.role_id
        WHERE $2
    ),
    resolved AS (
        SELECT s.*, p.kind, COALESCE(o.position, p.position) AS position
        FROM sources s
        JOIN security_permissions p ON p.id = s.permission_id
        LEFT JOIN security_permission_options o ON o.id = s.option_id
    )
    SELECT DISTINCT position, NULL::text AS text_value
    FROM resolved
    WHERE kind IN ('bool', 'multi')
    UNION ALL
    SELECT position, text_value
    FROM (
        SELECT DISTINCT ON (permission_id) position, text_value
        FROM resolved
        WHERE kind IN ('single', 'text')
        ORDER BY permission_id, rank, role_code
    ) winners
    ORDER BY position
"#;
