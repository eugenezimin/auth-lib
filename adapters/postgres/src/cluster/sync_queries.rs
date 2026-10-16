//! SQL for the federation-mode sync store: the change feed, session
//! aggregates, merged revocations / keys, snapshots and cursors.

/// Create this database's identity (enables feed capture).  Returns a row
/// only when it was just created.
pub const CREATE_SITE: &str = r#"
    INSERT INTO cluster_sync_site DEFAULT VALUES
    ON CONFLICT (singleton) DO NOTHING
    RETURNING site_id
"#;

pub const SELECT_SITE: &str = "SELECT site_id FROM cluster_sync_site";

/// When capture starts, every record already stored enters the feed, so a
/// cluster that reads it from the start gets everything.
pub const SEED_FEED: &str = r#"
    INSERT INTO cluster_change_feed (kind, key, seq, txid)
    SELECT kind, key, nextval('cluster_change_feed_seq'), pg_current_xact_id()
    FROM (
        SELECT 'session' AS kind, id::text AS key FROM security_sessions
        UNION ALL SELECT 'revocation', id::text FROM security_token_revocations WHERE expires_at > now()
        UNION ALL SELECT 'verifying_key', kid FROM security_verifying_keys
        UNION ALL SELECT 'account', user_id::text FROM cluster_account_snapshots
        UNION ALL SELECT 'catalog', 'catalog' FROM cluster_catalog_snapshot
    ) existing
    ON CONFLICT (kind, key) DO NOTHING
"#;

/// Entries after the cursor whose transaction is older than every running
/// one — so nothing still committing can be skipped.
///
/// `ORDER BY` names the table's column: a bare `txid` would mean the text
/// output alias, and text order breaks whenever transaction ids gain a
/// digit ('999' > '1000').
pub const CHANGES_SINCE: &str = r#"
    SELECT kind, key, seq, txid::text AS txid
    FROM cluster_change_feed
    WHERE (txid, seq) > ($1::text::xid8, $2)
      AND txid < pg_snapshot_xmin(pg_current_snapshot())
    ORDER BY cluster_change_feed.txid, seq
    LIMIT $3
"#;

/// The newest safe entry; ordered by the column, as in [`CHANGES_SINCE`].
pub const HEAD: &str = r#"
    SELECT txid::text AS txid, seq
    FROM cluster_change_feed
    WHERE txid < pg_snapshot_xmin(pg_current_snapshot())
    ORDER BY cluster_change_feed.txid DESC, seq DESC
    LIMIT 1
"#;

// ── sessions ──────────────────────────────────────────────────────────────────

pub const LOAD_SESSION: &str = r#"
    SELECT id, user_id, secret, status, end_reason, created_ip, user_agent, amr,
           current_generation, created_at, idle_expires_at, absolute_expires_at, ended_at,
           merge_rev
    FROM security_sessions
    WHERE id = $1
"#;

pub const LOAD_GENERATIONS: &str = r#"
    SELECT id, session_id, generation, issued_ip, issued_at, access_expires_at, superseded_at,
           parent_jti, issued_user_agent, fingerprint_hash, '{}'::uuid[] AS aliases
    FROM security_session_generations
    WHERE session_id = $1
    ORDER BY generation
"#;

pub const LOAD_ALIASES: &str = r#"
    SELECT jti, generation, parent_jti, issued_ip, issued_user_agent, fingerprint_hash,
           issued_at, access_expires_at, superseded_at
    FROM security_session_fork_aliases
    WHERE session_id = $1
    ORDER BY generation, jti
"#;

pub const LOCK_SESSION_REV: &str =
    "SELECT merge_rev FROM security_sessions WHERE id = $1 FOR UPDATE";

pub const INSERT_SESSION_WITH_ID: &str = r#"
    INSERT INTO security_sessions (id, user_id, secret, status, end_reason, created_ip, user_agent,
                          current_generation, created_at, idle_expires_at, absolute_expires_at,
                          ended_at, amr, merge_rev)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1)
"#;

pub const UPDATE_MERGED_SESSION: &str = r#"
    UPDATE security_sessions
    SET status = $2, end_reason = $3, current_generation = $4, idle_expires_at = $5,
        ended_at = $6, amr = $7, merge_rev = merge_rev + 1
    WHERE id = $1
"#;

pub const DELETE_GENERATIONS: &str =
    "DELETE FROM security_session_generations WHERE session_id = $1";
pub const DELETE_ALIASES: &str = "DELETE FROM security_session_fork_aliases WHERE session_id = $1";

pub const INSERT_GENERATION_WITH_ID: &str = r#"
    INSERT INTO security_session_generations (id, session_id, generation, issued_ip, issued_at,
                                     access_expires_at, superseded_at, parent_jti,
                                     issued_user_agent, fingerprint_hash)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
"#;

pub const INSERT_ALIAS: &str = r#"
    INSERT INTO security_session_fork_aliases (jti, session_id, generation, parent_jti, issued_ip,
                                            issued_user_agent, fingerprint_hash, issued_at,
                                            access_expires_at, superseded_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
"#;

pub const ACTIVE_SESSION_IDS: &str = r#"
    SELECT id FROM security_sessions WHERE user_id = $1 AND status = 'active' ORDER BY id
"#;

// ── revocations and keys (merged under a row lock) ────────────────────────────

pub const LOCK_REVOCATION: &str = r#"
    SELECT id, scope, subject, reason, status, origin_node, revoked_at, expires_at,
           enforced_at, enforced_by
    FROM security_token_revocations WHERE id = $1 FOR UPDATE
"#;

pub const SELECT_REVOCATION: &str = r#"
    SELECT id, scope, subject, reason, status, origin_node, revoked_at, expires_at,
           enforced_at, enforced_by
    FROM security_token_revocations WHERE id = $1
"#;

pub const INSERT_REVOCATION_WITH_ID: &str = r#"
    INSERT INTO security_token_revocations (id, scope, subject, reason, status, origin_node, revoked_at,
                             expires_at, enforced_at, enforced_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ON CONFLICT (id) DO NOTHING
"#;

pub const UPDATE_MERGED_REVOCATION: &str = r#"
    UPDATE security_token_revocations
    SET reason = $2, status = $3, origin_node = $4, revoked_at = $5, expires_at = $6,
        enforced_at = $7, enforced_by = $8
    WHERE id = $1
"#;

pub const LOCK_KEY: &str = r#"
    SELECT kid, public_key, status, published_by, created_at, revoked_at
    FROM security_verifying_keys WHERE kid = $1 FOR UPDATE
"#;

pub const SELECT_KEY: &str = r#"
    SELECT kid, public_key, status, published_by, created_at, revoked_at
    FROM security_verifying_keys WHERE kid = $1
"#;

pub const INSERT_KEY_FULL: &str = r#"
    INSERT INTO security_verifying_keys (kid, public_key, status, published_by, created_at, revoked_at)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (kid) DO NOTHING
"#;

pub const UPDATE_MERGED_KEY: &str = r#"
    UPDATE security_verifying_keys
    SET status = $2, published_by = $3, created_at = $4, revoked_at = $5
    WHERE kid = $1
"#;

// ── snapshots ─────────────────────────────────────────────────────────────────

pub const APPLY_ACCOUNT: &str = r#"
    INSERT INTO cluster_account_snapshots (user_id, version, is_active, deleted, authz)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (user_id) DO UPDATE
    SET version = EXCLUDED.version, is_active = EXCLUDED.is_active,
        deleted = EXCLUDED.deleted, authz = EXCLUDED.authz, updated_at = now()
    WHERE cluster_account_snapshots.version < EXCLUDED.version
"#;

pub const LOAD_ACCOUNT: &str = r#"
    SELECT user_id, version, is_active, deleted, authz
    FROM cluster_account_snapshots WHERE user_id = $1
"#;

pub const NEXT_ACCOUNT_VERSION: &str = "SELECT nextval('cluster_account_snapshot_version_seq')";

pub const APPLY_CATALOG: &str = r#"
    INSERT INTO cluster_catalog_snapshot (singleton, version, catalog)
    VALUES (true, $1, $2)
    ON CONFLICT (singleton) DO UPDATE
    SET version = EXCLUDED.version, catalog = EXCLUDED.catalog, updated_at = now()
    WHERE cluster_catalog_snapshot.version < EXCLUDED.version
"#;

pub const LOAD_CATALOG: &str = "SELECT version, catalog FROM cluster_catalog_snapshot";

// ── cursors ───────────────────────────────────────────────────────────────────

pub const LOAD_CURSOR: &str = "SELECT txid, seq FROM cluster_feed_cursors WHERE site_id = $1";

pub const ADVANCE_CURSOR: &str = r#"
    INSERT INTO cluster_feed_cursors (site_id, txid, seq) VALUES ($1, $2, $3)
    ON CONFLICT (site_id) DO UPDATE
    SET txid = EXCLUDED.txid, seq = EXCLUDED.seq, updated_at = now()
    WHERE (cluster_feed_cursors.txid, cluster_feed_cursors.seq) < (EXCLUDED.txid, EXCLUDED.seq)
"#;

pub const RESET_CURSOR: &str = "DELETE FROM cluster_feed_cursors WHERE site_id = $1";

// ── freshness ─────────────────────────────────────────────────────────────────

pub const RECORD_CAUGHT_UP: &str = r#"
    INSERT INTO cluster_sync_freshness (service, caught_up_at) VALUES ($1, $2)
    ON CONFLICT (service) DO UPDATE
    SET caught_up_at = GREATEST(cluster_sync_freshness.caught_up_at, EXCLUDED.caught_up_at)
"#;

pub const CAUGHT_UP_AT: &str = "SELECT caught_up_at FROM cluster_sync_freshness WHERE service = $1";
