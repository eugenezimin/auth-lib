-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: z_auth
-- Migration 0001 — initial schema (z-auth core)
-- -------------------------------------------------------------
--
-- Applied by sqlx's migrator (see `z_auth_postgres::MIGRATOR`), which
-- records it in `_sqlx_migrations`.  Never edit this file once applied
-- anywhere — add `0002_<description>.sql` instead.
--
-- This baseline replaces the earlier migrations 0001–0008: a database built
-- with those must be rebuilt (`setup_db --reset`).
--
-- Naming: every table is prefixed with the z-auth layer that owns it —
-- `identity_` (users, roles), `security_` (permissions, sessions, tokens).
-- Constraints, indexes, sequences and triggers embed their table's name.
-- The `cluster_` tables of z-auth-cluster are a separate migration set
-- (`migrations_cluster/`, versions from 1001), applied on top of this one.
--
-- Conventions:
--   * every table has a surrogate `id uuid` primary key (gen_random_uuid())
--     unless a natural key exists;
--   * every table has `created_at` — when the row was inserted;
--   * the database is the only time source: timestamps default to now()
--     and z-auth passes durations, never instants;
--   * all timestamps are `timestamptz` (stored as UTC instants; the adapter
--     also pins each connection's TimeZone to UTC);
--   * closed value sets are ENUM types.

-- ── Enum types ────────────────────────────────────────────────────────────────
-- Adding a value later: ALTER TYPE ... ADD VALUE '...' in a new migration.
-- Values can't be removed or reordered without recreating the type.

CREATE TYPE session_status AS ENUM ('active', 'revoked', 'compromised');

CREATE TYPE revocation_scope AS ENUM ('session', 'user', 'token');

CREATE TYPE revocation_reason AS ENUM (
    'logout',
    'logout_all',
    'evicted',
    'token_reuse',
    'ip_mismatch',
    'compromised',
    'administrative',
    'password_changed',
    'account_disabled',
    'account_deleted',
    -- A token covered by a pending revocation was presented: the session
    -- is marked compromised with this reason.
    'revoked_token_used',
    -- The losing access token of a benign refresh fork, revoked on its own
    -- (scope 'token').
    'concurrent_refresh'
);

CREATE TYPE revocation_status AS ENUM ('pending', 'enforced');

CREATE TYPE permission_kind AS ENUM ('bool', 'single', 'multi', 'text');

CREATE TYPE verifying_key_status AS ENUM ('active', 'revoked');

-- ═════════════════════════════════════════════════════════════════════════════
-- identity — users, roles and role assignments
-- ═════════════════════════════════════════════════════════════════════════════

-- ── identity_roles ────────────────────────────────────────────────────────────
-- Immutable once created (no update API), so no updated_at.  `code` is the
-- immutable identifier carried in tokens (`rol`).
CREATE TABLE "identity_roles" (
    "id"          uuid         NOT NULL DEFAULT gen_random_uuid(),
    "name"        varchar(50)  NOT NULL,
    "description" text,
    "created_at"  timestamptz  NOT NULL DEFAULT now(),
    "code"        varchar(64)  NOT NULL,
    PRIMARY KEY ("id"),
    CONSTRAINT chk_identity_roles_code_format
        CHECK ("code" ~ '^[a-z][a-z0-9_.:-]*$')
);

CREATE UNIQUE INDEX identity_roles_name_key ON identity_roles USING btree (name);
CREATE UNIQUE INDEX identity_roles_code_key ON identity_roles USING btree (code);

-- ── identity_users ────────────────────────────────────────────────────────────
-- The only table with free-form edits, hence the only one with updated_at
-- (set explicitly by every UPDATE query — no trigger overhead).
CREATE TABLE "identity_users" (
    "id"            uuid         NOT NULL DEFAULT gen_random_uuid(),
    "email"         varchar(255) NOT NULL,
    "password_hash" text,
    "username"      varchar(100),
    "first_name"    varchar(255),
    "last_name"     varchar(255),
    "avatar_url"    text,
    "is_active"     bool         NOT NULL DEFAULT true,
    "is_verified"   bool         NOT NULL DEFAULT false,
    "created_at"    timestamptz  NOT NULL DEFAULT now(),
    "updated_at"    timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);

-- Case-insensitive uniqueness.  Emails are lowercased by z-auth before
-- they reach the database; usernames keep their display case, so lookups
-- compare lower(username) = lower($1).
CREATE UNIQUE INDEX identity_users_email        ON identity_users USING btree (lower(email));
CREATE UNIQUE INDEX identity_users_username_key ON identity_users USING btree (lower(username));

-- ── identity_role_assignments ─────────────────────────────────────────────────
-- revoked_at is NULL while the assignment is active; set to the revocation
-- timestamp when the role is withdrawn.  This keeps the full audit trail
-- without a separate history table.  assigned_at is the business event;
-- created_at is row bookkeeping (equal today, independent by design).
CREATE TABLE "identity_role_assignments" (
    "id"          uuid        NOT NULL DEFAULT gen_random_uuid(),
    "user_id"     uuid        NOT NULL,
    "role_id"     uuid        NOT NULL,
    "assigned_at" timestamptz NOT NULL DEFAULT now(),
    "revoked_at"  timestamptz,                         -- NULL → active
    "created_at"  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_identity_role_assignments_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users"("id") ON DELETE CASCADE,
    CONSTRAINT fk_identity_role_assignments_role_id
        FOREIGN KEY ("role_id") REFERENCES "identity_roles"("id") ON DELETE CASCADE,
    CONSTRAINT chk_identity_role_assignments_revoked_after_assigned
        CHECK ("revoked_at" IS NULL OR "revoked_at" >= "assigned_at")
);

-- Uniqueness is scoped to *active* assignments only: the same (user, role)
-- pair may appear multiple times historically, but only once with
-- revoked_at IS NULL.
CREATE UNIQUE INDEX unique_user_role_active
    ON identity_role_assignments (user_id, role_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_identity_role_assignments_user_id
    ON identity_role_assignments USING btree (user_id);

CREATE INDEX idx_identity_role_assignments_role_id
    ON identity_role_assignments USING btree (role_id);

-- Partial index: fast lookup of every active assignment for a user.
CREATE INDEX idx_identity_role_assignments_active
    ON identity_role_assignments (user_id, assigned_at DESC)
    WHERE revoked_at IS NULL;

-- Partial index: fast lookup of revoked assignments (audit / reporting).
CREATE INDEX idx_identity_role_assignments_removed
    ON identity_role_assignments (user_id, revoked_at DESC)
    WHERE revoked_at IS NOT NULL;

-- ═════════════════════════════════════════════════════════════════════════════
-- security — permission catalog and grants, sessions, token revocations,
-- verifying keys
-- ═════════════════════════════════════════════════════════════════════════════

-- ── permission catalog ────────────────────────────────────────────────────────
-- Permissions are encoded into access tokens by *position*: every `bool`
-- and `text` permission and every option of a `single` / `multi`
-- permission takes a number from `security_permission_position_seq`.
-- Positions are permanent and never reused, so tokens and cached catalogs
-- stay decodable across catalog changes.

CREATE SEQUENCE security_permission_position_seq AS integer START 1;

CREATE TABLE "security_permissions" (
    "id"          uuid            NOT NULL DEFAULT gen_random_uuid(),
    "code"        varchar(64)     NOT NULL,
    "kind"        permission_kind NOT NULL,
    "description" text,
    "position"    integer,                     -- bool / text only
    "max_length"  integer,                     -- text only
    "created_at"  timestamptz     NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT chk_security_permissions_code_format
        CHECK ("code" ~ '^[a-z][a-z0-9_.:-]*$'),
    CONSTRAINT chk_security_permissions_position
        CHECK (("kind" IN ('bool', 'text')) = ("position" IS NOT NULL)),
    CONSTRAINT chk_security_permissions_max_length
        CHECK (("kind" = 'text') = ("max_length" IS NOT NULL) AND
               ("max_length" IS NULL OR "max_length" > 0))
);

CREATE UNIQUE INDEX security_permissions_code_key     ON security_permissions USING btree (code);
CREATE UNIQUE INDEX security_permissions_position_key ON security_permissions USING btree (position);

CREATE TABLE "security_permission_options" (
    "id"            uuid        NOT NULL DEFAULT gen_random_uuid(),
    "permission_id" uuid        NOT NULL,
    "code"          varchar(64) NOT NULL,
    "position"      integer     NOT NULL DEFAULT nextval('security_permission_position_seq'),
    "created_at"    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_security_permission_options_permission_id
        FOREIGN KEY ("permission_id") REFERENCES "security_permissions"("id") ON DELETE CASCADE,
    CONSTRAINT security_permission_options_permission_code_key
        UNIQUE ("permission_id", "code"),
    CONSTRAINT chk_security_permission_options_code_format
        CHECK ("code" ~ '^[a-z][a-z0-9_.:-]*$')
);

CREATE UNIQUE INDEX security_permission_options_position_key
    ON security_permission_options USING btree (position);

-- ── grants ────────────────────────────────────────────────────────────────────
-- One row per granted `bool` / `text` permission (option_id NULL) or per
-- chosen option.  Grant rows are replaced, never edited, so there is no
-- updated_at.  Kind consistency (which column is set) is enforced by
-- z-auth's PermissionService.

CREATE TABLE "security_user_grants" (
    "id"            uuid        NOT NULL DEFAULT gen_random_uuid(),
    "user_id"       uuid        NOT NULL,
    "permission_id" uuid        NOT NULL,
    "option_id"     uuid,
    "text_value"    text,
    "created_at"    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_security_user_grants_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users"("id") ON DELETE CASCADE,
    CONSTRAINT fk_security_user_grants_permission_id
        FOREIGN KEY ("permission_id") REFERENCES "security_permissions"("id") ON DELETE CASCADE,
    CONSTRAINT fk_security_user_grants_option_id
        FOREIGN KEY ("option_id") REFERENCES "security_permission_options"("id") ON DELETE CASCADE,
    CONSTRAINT chk_security_user_grants_shape
        CHECK ("option_id" IS NULL OR "text_value" IS NULL)
);

CREATE UNIQUE INDEX security_user_grants_value_key
    ON security_user_grants (user_id, permission_id) WHERE option_id IS NULL;
CREATE UNIQUE INDEX security_user_grants_option_key
    ON security_user_grants (user_id, option_id) WHERE option_id IS NOT NULL;

CREATE TABLE "security_role_grants" (
    "id"            uuid        NOT NULL DEFAULT gen_random_uuid(),
    "role_id"       uuid        NOT NULL,
    "permission_id" uuid        NOT NULL,
    "option_id"     uuid,
    "text_value"    text,
    "created_at"    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_security_role_grants_role_id
        FOREIGN KEY ("role_id") REFERENCES "identity_roles"("id") ON DELETE CASCADE,
    CONSTRAINT fk_security_role_grants_permission_id
        FOREIGN KEY ("permission_id") REFERENCES "security_permissions"("id") ON DELETE CASCADE,
    CONSTRAINT fk_security_role_grants_option_id
        FOREIGN KEY ("option_id") REFERENCES "security_permission_options"("id") ON DELETE CASCADE,
    CONSTRAINT chk_security_role_grants_shape
        CHECK ("option_id" IS NULL OR "text_value" IS NULL)
);

CREATE UNIQUE INDEX security_role_grants_value_key
    ON security_role_grants (role_id, permission_id) WHERE option_id IS NULL;
CREATE UNIQUE INDEX security_role_grants_option_key
    ON security_role_grants (role_id, option_id) WHERE option_id IS NOT NULL;

-- Login / refresh read a user's grants (direct, and via roles).
CREATE INDEX idx_security_user_grants_user_id
    ON security_user_grants USING btree (user_id);
CREATE INDEX idx_security_role_grants_role_id
    ON security_role_grants USING btree (role_id);

-- ── security_sessions ─────────────────────────────────────────────────────────
-- One row per login on one device.  No token material is stored: refresh
-- tokens are re-derived from (id, generation, secret) plus the server-wide
-- refresh key, and access tokens are identified by their jti only.
-- Every change is captured by a dedicated column (current_generation,
-- idle_expires_at, status/end_reason/ended_at), so no updated_at.
-- merge_rev is bumped by every session write, so merging a session from
-- another cluster (federation mode) can compare-and-swap against local
-- writes.
CREATE TABLE "security_sessions" (
    "id"                  uuid              NOT NULL DEFAULT gen_random_uuid(),
    "user_id"             uuid              NOT NULL,
    "secret"              bytea             NOT NULL,   -- mixed into refresh-token MACs
    "status"              session_status    NOT NULL DEFAULT 'active',
    "end_reason"          revocation_reason,            -- set when ended
    "created_ip"          inet              NOT NULL,
    "user_agent"          varchar(512),                 -- truncated by z-auth
    "current_generation"  integer           NOT NULL DEFAULT 1,
    "created_at"          timestamptz       NOT NULL DEFAULT now(),
    "idle_expires_at"     timestamptz       NOT NULL,   -- pushed forward on every refresh
    "absolute_expires_at" timestamptz       NOT NULL,   -- hard cap
    "ended_at"            timestamptz,
    "merge_rev"           bigint            NOT NULL DEFAULT 0,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_security_sessions_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users"("id") ON DELETE CASCADE,
    CONSTRAINT chk_security_sessions_generation_positive
        CHECK ("current_generation" >= 1),
    -- Active ⇔ not ended: an ended session always has both a time and a reason.
    CONSTRAINT chk_security_sessions_ended
        CHECK ((("status" = 'active') = ("ended_at" IS NULL))
           AND (("status" = 'active') = ("end_reason" IS NULL)))
);

-- Active sessions per user, oldest first (session cap, logout-all).
-- Partial, so ended sessions awaiting purge don't bloat it.
CREATE INDEX idx_security_sessions_user_active
    ON security_sessions (user_id, created_at)
    WHERE status = 'active';

-- Housekeeping: the moment a session became purgeable.  The purge query
-- must repeat this expression verbatim to use the index.
CREATE INDEX idx_security_sessions_purge
    ON security_sessions (LEAST(idle_expires_at, absolute_expires_at,
                                COALESCE(ended_at, 'infinity')));

-- ── security_session_generations ──────────────────────────────────────────────
-- Token rotation history: the newest N generations of each session are kept
-- for reuse detection (N = session history size, default 10).
-- The row's id doubles as the access token's jti.
--   parent_jti         the access token presented to obtain the generation;
--                      tells a client retrying at two services (same parent)
--                      apart from a stolen token used on a later generation.
--   issued_user_agent  compared by AUTH_REFRESH_RETRY_MATCH=user_agent.
--   fingerprint_hash   SHA-256 of the host-supplied client fingerprint,
--                      compared by AUTH_REFRESH_RETRY_MATCH=fingerprint.
CREATE TABLE "security_session_generations" (
    "id"                uuid        NOT NULL DEFAULT gen_random_uuid(),  -- = access-token jti
    "session_id"        uuid        NOT NULL,
    "generation"        integer     NOT NULL,
    "issued_ip"         inet        NOT NULL,
    "issued_at"         timestamptz NOT NULL DEFAULT now(),
    "access_expires_at" timestamptz NOT NULL,
    "superseded_at"     timestamptz,                     -- set when generation + 1 is issued
    "created_at"        timestamptz NOT NULL DEFAULT now(),
    "parent_jti"        uuid,
    "issued_user_agent" varchar(512),
    "fingerprint_hash"  bytea,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_security_session_generations_session_id
        FOREIGN KEY ("session_id") REFERENCES "security_sessions"("id") ON DELETE CASCADE,
    CONSTRAINT security_session_generations_session_generation_key
        UNIQUE ("session_id", "generation"),
    CONSTRAINT chk_security_session_generations_positive
        CHECK ("generation" >= 1),
    CONSTRAINT chk_security_session_generations_fingerprint
        CHECK ("fingerprint_hash" IS NULL OR octet_length("fingerprint_hash") = 32)
);

-- ── security_session_fork_aliases ─────────────────────────────────────────────
-- Federation mode: when two services rotated the same generation and the
-- fork was benign, the losing variants are kept here.  Their `jti` is
-- accepted like the winner's, so the client holding that pair refreshes
-- once into the winning chain.  Empty in the other modes.
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
-- Persisted denylist, append-only.  Every server periodically loads the
-- unexpired rows into memory.  A row only needs to live for the access-token
-- TTL + leeway, so the table stays small.  A revocation starts `pending`
-- and becomes `enforced` once a covered token is presented and blocked.
CREATE TABLE "security_token_revocations" (
    "id"          uuid              NOT NULL DEFAULT gen_random_uuid(),
    "scope"       revocation_scope  NOT NULL,
    "subject"     uuid              NOT NULL,            -- session | user | token id
    "reason"      revocation_reason NOT NULL,
    "revoked_at"  timestamptz       NOT NULL DEFAULT now(),
    "expires_at"  timestamptz       NOT NULL,
    "created_at"  timestamptz       NOT NULL DEFAULT now(),
    "status"      revocation_status NOT NULL DEFAULT 'pending',
    "origin_node" uuid,                                  -- the issuing instance
    "enforced_at" timestamptz,
    "enforced_by" uuid,
    PRIMARY KEY ("id"),
    CONSTRAINT chk_security_token_revocations_enforced
        CHECK (("status" = 'enforced') = ("enforced_at" IS NOT NULL))
);

-- list_active() and purge_expired().
CREATE INDEX idx_security_token_revocations_expires_at
    ON security_token_revocations USING btree (expires_at);

-- ── security_verifying_keys ───────────────────────────────────────────────────
-- Public Ed25519 keys published by instances; private keys never leave
-- their instance.
CREATE TABLE "security_verifying_keys" (
    "id"           uuid                 NOT NULL DEFAULT gen_random_uuid(),
    "kid"          varchar(32)          NOT NULL,      -- JWT key id
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

CREATE UNIQUE INDEX security_verifying_keys_kid_key
    ON security_verifying_keys USING btree (kid);
