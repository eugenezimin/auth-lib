//! SQL query constants for published verifying keys.

/// Idempotent per kid: an existing key (active or revoked) is returned as is.
pub const PUBLISH_KEY: &str = r#"
    WITH inserted AS (
        INSERT INTO security_verifying_keys (kid, public_key, published_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (kid) DO NOTHING
        RETURNING kid, public_key, status, published_by, created_at, revoked_at
    )
    SELECT kid, public_key, status, published_by, created_at, revoked_at FROM inserted
    UNION ALL
    SELECT kid, public_key, status, published_by, created_at, revoked_at
    FROM security_verifying_keys WHERE kid = $1
    LIMIT 1
"#;

pub const REVOKE_KEY: &str = r#"
    UPDATE security_verifying_keys
    SET status = 'revoked', revoked_at = COALESCE(revoked_at, now())
    WHERE kid = $1
    RETURNING kid, public_key, status, published_by, created_at, revoked_at
"#;

pub const LIST_KEYS: &str = r#"
    SELECT kid, public_key, status, published_by, created_at, revoked_at
    FROM security_verifying_keys
    ORDER BY kid
"#;
