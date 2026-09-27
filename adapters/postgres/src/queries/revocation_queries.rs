//! SQL query constants for the `revocations` table (persisted denylist).
//! Timestamps come from `now()`; the caller binds only the entry's TTL.

pub const INSERT_REVOCATION: &str = r#"
    INSERT INTO revocations (scope, subject, reason, expires_at)
    VALUES ($1, $2, $3, now() + $4)
    RETURNING scope, subject, reason, revoked_at, expires_at
"#;

pub const LIST_ACTIVE: &str = r#"
    SELECT scope, subject, reason, revoked_at, expires_at
    FROM revocations
    WHERE expires_at > now()
"#;

pub const PURGE_EXPIRED: &str = r#"
    DELETE FROM revocations WHERE expires_at <= now()
"#;
