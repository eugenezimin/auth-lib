//! SQL query constants for the cluster node registry (`cluster_nodes`).

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

// ── Federation mode ──────────────────────────────────────────────────────────

/// Lock the target and the observer, in id order, so two instances evicting
/// each other are serialised: the second sees itself missing.
pub const LOCK_NODES_FOR_EVICTION: &str = r#"
    SELECT id, heartbeat FROM cluster_nodes
    WHERE id = ANY($1)
    ORDER BY id
    FOR UPDATE
"#;

/// heartbeat → missing (evicted; id retired)
pub const EVICT_NODE: &str = r#"
    UPDATE cluster_nodes
    SET heartbeat = 'missing', heartbeat_changed_at = now(), retired_at = now()
    WHERE id = $1 AND heartbeat <> 'missing'
"#;

/// A running node's address changed.
pub const UPDATE_NODE_ADDRESS: &str = r#"
    UPDATE cluster_nodes SET ip = $2, dns_name = $3, port = $4
    WHERE id = $1 AND heartbeat <> 'missing'
      AND (ip IS DISTINCT FROM $2 OR dns_name IS DISTINCT FROM $3 OR port <> $4)
"#;

pub const PURGE_RETIRED_NODES: &str = r#"
    DELETE FROM cluster_nodes
    WHERE heartbeat = 'missing' AND retired_at < now() - make_interval(secs => $1)
"#;

pub const LIST_NODES: &str = r#"
    SELECT id, service, ip, dns_name, port, version, state, heartbeat, started_at,
           state_changed_at, heartbeat_changed_at
    FROM cluster_nodes
    ORDER BY started_at
"#;
