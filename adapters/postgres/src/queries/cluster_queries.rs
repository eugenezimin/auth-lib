//! SQL query constants for the node registry and published verifying keys.

// ── Node registry: a state machine.  Every write is guarded by the state
// it starts from, so concurrent observers change a row at most once.

/// A node starts: insert it (or reset a leftover row) as joining / online.
pub const REGISTER_NODE: &str = r#"
    INSERT INTO cluster_nodes (id, service, ip, dns_name, port, version, state, heartbeat,
                               started_at)
    VALUES ($1, $2, $3, $4, $5, $6, 'joining', 'online', $7)
    ON CONFLICT (id) DO UPDATE
    SET service = EXCLUDED.service, ip = EXCLUDED.ip, dns_name = EXCLUDED.dns_name,
        port = EXCLUDED.port, version = EXCLUDED.version,
        state = 'joining', heartbeat = 'online',
        state_changed_at = now(), heartbeat_changed_at = now()
"#;

/// Re-add a node heard again: insert as `$7` / online, or bring an existing
/// offline row back online.  No change if it is present and online.
pub const RESTORE_NODE: &str = r#"
    INSERT INTO cluster_nodes (id, service, ip, dns_name, port, version, state, heartbeat,
                               started_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, 'online', $8)
    ON CONFLICT (id) DO UPDATE
    SET heartbeat = 'online', heartbeat_changed_at = now()
    WHERE cluster_nodes.heartbeat = 'offline'
"#;

/// joining → active
pub const ACTIVATE_NODE: &str = r#"
    UPDATE cluster_nodes SET state = 'active', state_changed_at = now()
    WHERE id = $1 AND state = 'joining'
"#;

/// joining | active → leaving
pub const BEGIN_LEAVE_NODE: &str = r#"
    UPDATE cluster_nodes SET state = 'leaving', state_changed_at = now()
    WHERE id = $1 AND state <> 'leaving'
"#;

/// leaving → (deleted)
pub const REMOVE_NODE: &str = r#"
    DELETE FROM cluster_nodes WHERE id = $1 AND state = 'leaving'
"#;

/// heartbeat online → offline
pub const MARK_NODE_OFFLINE: &str = r#"
    UPDATE cluster_nodes SET heartbeat = 'offline', heartbeat_changed_at = now()
    WHERE id = $1 AND heartbeat = 'online'
"#;

/// heartbeat offline → online
pub const MARK_NODE_ONLINE: &str = r#"
    UPDATE cluster_nodes SET heartbeat = 'online', heartbeat_changed_at = now()
    WHERE id = $1 AND heartbeat = 'offline'
"#;

/// heartbeat offline → (deleted)
pub const EXPIRE_NODE: &str = r#"
    DELETE FROM cluster_nodes WHERE id = $1 AND heartbeat = 'offline'
"#;

pub const LIST_NODES: &str = r#"
    SELECT id, service, ip, dns_name, port, version, state, heartbeat, started_at,
           state_changed_at, heartbeat_changed_at
    FROM cluster_nodes
    ORDER BY started_at
"#;

/// Idempotent per kid: an existing key (active or revoked) is returned as is.
pub const PUBLISH_KEY: &str = r#"
    WITH inserted AS (
        INSERT INTO verifying_keys (kid, public_key, published_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (kid) DO NOTHING
        RETURNING kid, public_key, status, published_by, created_at, revoked_at
    )
    SELECT kid, public_key, status, published_by, created_at, revoked_at FROM inserted
    UNION ALL
    SELECT kid, public_key, status, published_by, created_at, revoked_at
    FROM verifying_keys WHERE kid = $1
    LIMIT 1
"#;

pub const REVOKE_KEY: &str = r#"
    UPDATE verifying_keys
    SET status = 'revoked', revoked_at = COALESCE(revoked_at, now())
    WHERE kid = $1
    RETURNING kid, public_key, status, published_by, created_at, revoked_at
"#;

pub const LIST_KEYS: &str = r#"
    SELECT kid, public_key, status, published_by, created_at, revoked_at
    FROM verifying_keys
    ORDER BY kid
"#;
