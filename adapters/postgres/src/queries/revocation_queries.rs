//! SQL query constants for the `revocations` table (persisted denylist).
//! Timestamps come from `now()`; the caller binds only the entry's TTL.

pub const INSERT_REVOCATION: &str = r#"
    INSERT INTO revocations (scope, subject, reason, origin_node, expires_at)
    VALUES ($1, $2, $3, $4, now() + $5)
    RETURNING id, scope, subject, reason, status, origin_node, revoked_at, expires_at,
              enforced_at, enforced_by
"#;

/// Compare-and-swap `pending → enforced`; no row returned if another
/// instance got there first.
pub const MARK_ENFORCED: &str = r#"
    UPDATE revocations
    SET status = 'enforced', enforced_at = now(), enforced_by = $2
    WHERE id = $1 AND status = 'pending'
    RETURNING id, scope, subject, reason, status, origin_node, revoked_at, expires_at,
              enforced_at, enforced_by
"#;

pub const LIST_ACTIVE: &str = r#"
    SELECT id, scope, subject, reason, status, origin_node, revoked_at, expires_at,
           enforced_at, enforced_by
    FROM revocations
    WHERE expires_at > now()
"#;

pub const PURGE_EXPIRED: &str = r#"
    DELETE FROM revocations WHERE expires_at <= now()
"#;
