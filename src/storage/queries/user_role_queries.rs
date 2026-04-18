/// SQL query constants for the `users_roles` table.
///
/// All queries use `$N` positional parameters — values are never interpolated.
///
/// The table tracks full assignment history:
/// - `revoked_at IS NULL`  → active assignment
/// - `revoked_at IS NOT NULL` → revoked (retained for audit)

/// Insert a new active assignment row and return it fully hydrated.
pub const INSERT_USER_ROLE: &str = r#"
    INSERT INTO users_roles (user_id, role_id)
    VALUES ($1, $2)
    ON CONFLICT DO NOTHING
    RETURNING id, user_id, role_id, assigned_at, revoked_at
"#;

/// Stamp `revoked_at = NOW()` on the single active assignment for a
/// `(user_id, role_id)` pair.  The `WHERE revoked_at IS NULL` clause
/// ensures only the live assignment is affected; historical rows are
/// left untouched.
pub const REVOKE_USER_ROLE: &str = r#"
    UPDATE users_roles
    SET    revoked_at = CURRENT_TIMESTAMP
    WHERE  user_id    = $1
      AND  role_id    = $2
      AND  revoked_at IS NULL
    RETURNING id, user_id, role_id, assigned_at, revoked_at
"#;

/// All **active** assignments for a user, newest first.
/// Uses the partial index `idx_users_roles_active`.
pub const LIST_ACTIVE_FOR_USER: &str = r#"
    SELECT id, user_id, role_id, assigned_at, revoked_at
    FROM   users_roles
    WHERE  user_id    = $1
      AND  revoked_at IS NULL
    ORDER  BY assigned_at DESC
"#;

/// Full history (active + revoked) for a user, newest first.
pub const LIST_ALL_FOR_USER: &str = r#"
    SELECT id, user_id, role_id, assigned_at, revoked_at
    FROM   users_roles
    WHERE  user_id = $1
    ORDER  BY assigned_at DESC
"#;

/// Returns `true` if an active `(user_id, role_id)` assignment exists.
pub const IS_ROLE_ACTIVE: &str = r#"
    SELECT EXISTS(
        SELECT 1
        FROM   users_roles
        WHERE  user_id    = $1
          AND  role_id    = $2
          AND  revoked_at IS NULL
    )
"#;

/// Revoke **all** active assignments for a user in one statement.
/// Returns the count of updated rows via `sqlx`'s `rows_affected()`.
pub const REVOKE_ALL_FOR_USER: &str = r#"
    UPDATE users_roles
    SET    revoked_at = CURRENT_TIMESTAMP
    WHERE  user_id    = $1
      AND  revoked_at IS NULL
"#;
