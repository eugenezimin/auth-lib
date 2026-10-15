-- -------------------------------------------------------------
-- Session store — schema for every service except the authority (UMS)
-- in federation mode
-- -------------------------------------------------------------
--
-- Applied by `z_auth_postgres::SESSION_STORE_MIGRATOR`.  Holds only what
-- a refresh needs: sessions with their generations (and fork aliases),
-- token revocations, verifying keys, and the account / catalog snapshots
-- the authority publishes — no users, roles, grants or password hashes.
-- Plus this service's own instance registry and the change feed.
--
-- This baseline replaces the earlier session-store migrations 0001–0002: a
-- store built with those must be rebuilt.
--
-- Same table and column definitions as the authority's schema
-- (migrations/0001_initial_schema.sql), so the same repositories work on
-- both; the one difference is that security_sessions.user_id references
-- nothing here.  Object names are not schema-qualified: put the store in
-- its own schema with search_path.

CREATE TYPE session_status       AS ENUM ('active', 'revoked', 'compromised');
CREATE TYPE revocation_scope     AS ENUM ('session', 'user', 'token');
CREATE TYPE revocation_reason    AS ENUM (
    'logout', 'logout_all', 'evicted', 'token_reuse', 'ip_mismatch', 'compromised',
    'administrative', 'password_changed', 'account_disabled', 'account_deleted',
    'revoked_token_used', 'concurrent_refresh'
);
CREATE TYPE revocation_status    AS ENUM ('pending', 'enforced');
CREATE TYPE node_state           AS ENUM ('joining', 'active', 'leaving');
CREATE TYPE heartbeat_status     AS ENUM ('online', 'offline', 'missing');
CREATE TYPE verifying_key_status AS ENUM ('active', 'revoked');

-- ═════════════════════════════════════════════════════════════════════════════
-- security — sessions, token revocations, verifying keys
-- ═════════════════════════════════════════════════════════════════════════════

-- ── security_sessions ─────────────────────────────────────────────────────────
CREATE TABLE "security_sessions" (
    "id"                  uuid              NOT NULL DEFAULT gen_random_uuid(),
    "user_id"             uuid              NOT NULL,   -- a user of the authority
    "secret"              bytea             NOT NULL,
    "status"              session_status    NOT NULL DEFAULT 'active',
    "end_reason"          revocation_reason,
    "created_ip"          inet              NOT NULL,
    "user_agent"          varchar(512),
    "current_generation"  integer           NOT NULL DEFAULT 1,
    "created_at"          timestamptz       NOT NULL DEFAULT now(),
    "idle_expires_at"     timestamptz       NOT NULL,
    "absolute_expires_at" timestamptz       NOT NULL,
    "ended_at"            timestamptz,
    "merge_rev"           bigint            NOT NULL DEFAULT 0,
    PRIMARY KEY ("id"),
    CONSTRAINT chk_security_sessions_generation_positive CHECK ("current_generation" >= 1),
    CONSTRAINT chk_security_sessions_ended
        CHECK ((("status" = 'active') = ("ended_at" IS NULL))
           AND (("status" = 'active') = ("end_reason" IS NULL)))
);

CREATE INDEX idx_security_sessions_user_active
    ON "security_sessions" (user_id, created_at) WHERE status = 'active';
CREATE INDEX idx_security_sessions_purge
    ON "security_sessions" (LEAST(idle_expires_at, absolute_expires_at,
                                  COALESCE(ended_at, 'infinity')));

-- ── security_session_generations ──────────────────────────────────────────────
CREATE TABLE "security_session_generations" (
    "id"                uuid        NOT NULL DEFAULT gen_random_uuid(),
    "session_id"        uuid        NOT NULL,
    "generation"        integer     NOT NULL,
    "issued_ip"         inet        NOT NULL,
    "issued_at"         timestamptz NOT NULL DEFAULT now(),
    "access_expires_at" timestamptz NOT NULL,
    "superseded_at"     timestamptz,
    "created_at"        timestamptz NOT NULL DEFAULT now(),
    "parent_jti"        uuid,
    "issued_user_agent" varchar(512),
    "fingerprint_hash"  bytea,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_security_session_generations_session_id
        FOREIGN KEY ("session_id") REFERENCES "security_sessions"("id") ON DELETE CASCADE,
    CONSTRAINT security_session_generations_session_generation_key
        UNIQUE ("session_id", "generation"),
    CONSTRAINT chk_security_session_generations_positive CHECK ("generation" >= 1),
    CONSTRAINT chk_security_session_generations_fingerprint
        CHECK ("fingerprint_hash" IS NULL OR octet_length("fingerprint_hash") = 32)
);

-- ── security_session_fork_aliases ─────────────────────────────────────────────
CREATE TABLE "security_session_fork_aliases" (
    "jti"               uuid        NOT NULL,
    "session_id"        uuid        NOT NULL,
    "generation"        integer     NOT NULL,
    "parent_jti"        uuid,
    "issued_ip"         inet        NOT NULL,
    "issued_user_agent" varchar(512),
    "fingerprint_hash"  bytea,
    "issued_at"         timestamptz NOT NULL,
    "access_expires_at" timestamptz NOT NULL,
    "superseded_at"     timestamptz,
    "created_at"        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("jti"),
    CONSTRAINT fk_security_session_fork_aliases_session
        FOREIGN KEY ("session_id") REFERENCES "security_sessions" ("id") ON DELETE CASCADE,
    CONSTRAINT chk_security_session_fork_aliases_generation CHECK ("generation" >= 1),
    CONSTRAINT chk_security_session_fork_aliases_fingerprint
        CHECK ("fingerprint_hash" IS NULL OR octet_length("fingerprint_hash") = 32)
);

CREATE INDEX idx_security_session_fork_aliases_session
    ON "security_session_fork_aliases" ("session_id", "generation");

-- ── security_token_revocations ────────────────────────────────────────────────
CREATE TABLE "security_token_revocations" (
    "id"          uuid              NOT NULL DEFAULT gen_random_uuid(),
    "scope"       revocation_scope  NOT NULL,
    "subject"     uuid              NOT NULL,
    "reason"      revocation_reason NOT NULL,
    "revoked_at"  timestamptz       NOT NULL DEFAULT now(),
    "expires_at"  timestamptz       NOT NULL,
    "created_at"  timestamptz       NOT NULL DEFAULT now(),
    "status"      revocation_status NOT NULL DEFAULT 'pending',
    "origin_node" uuid,
    "enforced_at" timestamptz,
    "enforced_by" uuid,
    PRIMARY KEY ("id"),
    CONSTRAINT chk_security_token_revocations_enforced
        CHECK (("status" = 'enforced') = ("enforced_at" IS NOT NULL))
);

CREATE INDEX idx_security_token_revocations_expires_at
    ON "security_token_revocations" (expires_at);

-- ── security_verifying_keys ───────────────────────────────────────────────────
CREATE TABLE "security_verifying_keys" (
    "id"           uuid                 NOT NULL DEFAULT gen_random_uuid(),
    "kid"          varchar(32)          NOT NULL,
    "public_key"   bytea                NOT NULL,
    "status"       verifying_key_status NOT NULL DEFAULT 'active',
    "published_by" uuid,
    "revoked_at"   timestamptz,
    "created_at"   timestamptz          NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT chk_security_verifying_keys_length CHECK (octet_length("public_key") = 32),
    CONSTRAINT chk_security_verifying_keys_revoked
        CHECK (("status" = 'revoked') = ("revoked_at" IS NOT NULL))
);

CREATE UNIQUE INDEX security_verifying_keys_kid_key ON "security_verifying_keys" (kid);

-- ═════════════════════════════════════════════════════════════════════════════
-- cluster — this service's instances, snapshots and change feed
-- ═════════════════════════════════════════════════════════════════════════════

-- ── cluster_nodes ─────────────────────────────────────────────────────────────
CREATE TABLE "cluster_nodes" (
    "id"                   uuid             NOT NULL,
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

-- ── snapshots published by the authority ──────────────────────────────────────
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

CREATE TABLE "cluster_catalog_snapshot" (
    "singleton"  boolean     NOT NULL DEFAULT true,
    "version"    bigint      NOT NULL,
    "catalog"    jsonb       NOT NULL,
    "created_at" timestamptz NOT NULL DEFAULT now(),
    "updated_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("singleton"),
    CONSTRAINT chk_cluster_catalog_snapshot_singleton CHECK ("singleton")
);

-- ── change feed ───────────────────────────────────────────────────────────────
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

CREATE TABLE "cluster_feed_cursors" (
    "site_id"    uuid        NOT NULL,
    "txid"       bigint      NOT NULL,
    "seq"        bigint      NOT NULL,
    "updated_at" timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("site_id")
);

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
