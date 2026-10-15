-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: z_auth
-- Migration 1001 — cluster schema (z-auth-cluster, features `shared` /
-- `federation`)
-- -------------------------------------------------------------
--
-- Applied by `z_auth_postgres::CLUSTER_MIGRATOR`, after the core set
-- (`migrations/`): it adds the `cluster_` tables and the change-feed
-- triggers on the core `security_` tables.  Cluster versions start at 1001
-- so they never collide with core versions (both sets share
-- `_sqlx_migrations`).  Never edit this file once applied anywhere — add
-- `1002_<description>.sql` instead.

CREATE TYPE node_state       AS ENUM ('joining', 'active', 'leaving');
CREATE TYPE heartbeat_status AS ENUM ('online', 'offline', 'missing');

-- ═════════════════════════════════════════════════════════════════════════════
-- cluster — instance registry, federation snapshots and change feed
-- ═════════════════════════════════════════════════════════════════════════════

-- ── cluster_nodes ─────────────────────────────────────────────────────────────
-- The registry instances read at startup.  Two independent dimensions per
-- node, each changed only by its events:
--
--   state      joining ──► active ──► leaving ──► (row deleted)
--   heartbeat  online ──missed──► offline ──still silent──► missing / deleted
--
-- Every change is a guarded, idempotent write (`… WHERE state = 'joining'`),
-- so when several instances observe the same event exactly one changes the
-- row.  Steady-state heartbeats never write here.  In federation mode a
-- missing instance is evicted: its id is retired (`retired_at`) and the row
-- is kept until AUTH_CLUSTER_RETIRED_TTL_SECS has passed.  Shared mode never
-- uses 'missing'.
CREATE TABLE "cluster_nodes" (
    "id"                   uuid             NOT NULL,      -- node id, generated per process start
    "service"              varchar(100)     NOT NULL,
    "ip"                   inet,
    "dns_name"             varchar(253),
    "port"                 integer          NOT NULL,
    "version"              varchar(32)      NOT NULL,
    "started_at"           timestamptz      NOT NULL,
    "created_at"           timestamptz      NOT NULL DEFAULT now(),
    "state"                node_state       NOT NULL DEFAULT 'joining',
    "heartbeat"            heartbeat_status NOT NULL DEFAULT 'online',
    "state_changed_at"     timestamptz      NOT NULL DEFAULT now(),
    "heartbeat_changed_at" timestamptz      NOT NULL DEFAULT now(),
    "retired_at"           timestamptz,
    PRIMARY KEY ("id"),
    CONSTRAINT chk_cluster_nodes_port CHECK ("port" BETWEEN 1 AND 65535),
    CONSTRAINT chk_cluster_nodes_address CHECK ("ip" IS NOT NULL OR "dns_name" IS NOT NULL)
);

-- ── snapshots published by the authority (federation mode) ────────────────────
CREATE TABLE "cluster_account_snapshots" (
    "user_id"    uuid        NOT NULL,
    "version"    bigint      NOT NULL,
    "is_active"  boolean     NOT NULL,
    "deleted"    boolean     NOT NULL DEFAULT false,
    "authz"      jsonb,
    "created_at" timestamptz NOT NULL DEFAULT now(),
    "updated_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("user_id")
);

-- Versions handed out by the authority (one sequence: monotonic per user).
CREATE SEQUENCE cluster_account_snapshot_version_seq;

CREATE TABLE "cluster_catalog_snapshot" (
    "singleton"  boolean     NOT NULL DEFAULT true,
    "version"    bigint      NOT NULL,
    "catalog"    jsonb       NOT NULL,
    "created_at" timestamptz NOT NULL DEFAULT now(),
    "updated_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("singleton"),
    CONSTRAINT chk_cluster_catalog_snapshot_singleton CHECK ("singleton")
);

-- ── change feed (federation mode) ─────────────────────────────────────────────
-- cluster_change_feed holds one entry per synced record — its latest
-- change — written by trigger in the same transaction as the data, so
-- direct SQL edits are captured too.  Readers only serve entries whose
-- transaction is older than every running one
-- (`txid < pg_snapshot_xmin(pg_current_snapshot())`), so a change that is
-- still committing is never skipped.
--
-- Capture is off until the database is first used in federation mode
-- (cluster_sync_site gets its row); shared and standalone deployments pay
-- one cheap EXISTS per write.

-- This database's site id; its row switches capture on.
CREATE TABLE "cluster_sync_site" (
    "singleton"  boolean     NOT NULL DEFAULT true,
    "site_id"    uuid        NOT NULL DEFAULT gen_random_uuid(),
    "created_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("singleton"),
    CONSTRAINT chk_cluster_sync_site_singleton CHECK ("singleton")
);

CREATE SEQUENCE cluster_change_feed_seq;

CREATE TABLE "cluster_change_feed" (
    "kind"       text        NOT NULL,
    "key"        text        NOT NULL,
    "seq"        bigint      NOT NULL,
    "txid"       xid8        NOT NULL,
    "changed_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("kind", "key")
);

CREATE INDEX idx_cluster_change_feed_order ON "cluster_change_feed" ("txid", "seq");

-- How far this database has read each other cluster's feed.
CREATE TABLE "cluster_feed_cursors" (
    "site_id"    uuid        NOT NULL,
    "txid"       bigint      NOT NULL,
    "seq"        bigint      NOT NULL,
    "updated_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("site_id")
);

-- When this database last held everything a service had committed (written
-- by the instance that owns the link to it, read by every instance's
-- staleness guard).
CREATE TABLE "cluster_sync_freshness" (
    "service"       varchar(100) NOT NULL,
    "caught_up_at"  timestamptz  NOT NULL,
    PRIMARY KEY ("service")
);

CREATE FUNCTION cluster_feed_record(p_kind text, p_key text) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO cluster_change_feed (kind, key, seq, txid)
    VALUES (p_kind, p_key, nextval('cluster_change_feed_seq'), pg_current_xact_id())
    ON CONFLICT (kind, key) DO UPDATE
    SET seq = EXCLUDED.seq, txid = EXCLUDED.txid, changed_at = now()
$$;

-- The feed `kind` values ('session', 'revocation', …) are wire format, not
-- table names: they must not change with the tables.
CREATE FUNCTION cluster_feed_capture() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    r record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cluster_sync_site) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN r := OLD; ELSE r := NEW; END IF;
    CASE TG_TABLE_NAME
        WHEN 'security_sessions' THEN
            PERFORM cluster_feed_record('session', r.id::text);
        WHEN 'security_session_generations', 'security_session_fork_aliases' THEN
            PERFORM cluster_feed_record('session', r.session_id::text);
        WHEN 'security_token_revocations' THEN
            PERFORM cluster_feed_record('revocation', r.id::text);
        WHEN 'security_verifying_keys' THEN
            PERFORM cluster_feed_record('verifying_key', r.kid);
        WHEN 'cluster_account_snapshots' THEN
            PERFORM cluster_feed_record('account', r.user_id::text);
        WHEN 'cluster_catalog_snapshot' THEN
            PERFORM cluster_feed_record('catalog', 'catalog');
    END CASE;
    RETURN NULL;
END
$$;

CREATE TRIGGER trg_feed_security_sessions
    AFTER INSERT OR UPDATE OR DELETE ON "security_sessions"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
CREATE TRIGGER trg_feed_security_session_generations
    AFTER INSERT OR UPDATE OR DELETE ON "security_session_generations"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
CREATE TRIGGER trg_feed_security_session_fork_aliases
    AFTER INSERT OR UPDATE OR DELETE ON "security_session_fork_aliases"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
CREATE TRIGGER trg_feed_security_token_revocations
    AFTER INSERT OR UPDATE OR DELETE ON "security_token_revocations"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
CREATE TRIGGER trg_feed_security_verifying_keys
    AFTER INSERT OR UPDATE OR DELETE ON "security_verifying_keys"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
CREATE TRIGGER trg_feed_cluster_account_snapshots
    AFTER INSERT OR UPDATE OR DELETE ON "cluster_account_snapshots"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
CREATE TRIGGER trg_feed_cluster_catalog_snapshot
    AFTER INSERT OR UPDATE OR DELETE ON "cluster_catalog_snapshot"
    FOR EACH ROW EXECUTE FUNCTION cluster_feed_capture();
