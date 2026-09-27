-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: auth_lib
-- Migration 0001 — initial schema
-- -------------------------------------------------------------
--
-- Applied by sqlx's migrator (see `auth_lib_postgres::MIGRATOR`), which
-- records it in `_sqlx_migrations`.  Never edit this file once applied
-- anywhere — add `0002_<description>.sql` instead.
--
-- Conventions:
--   * every table has a surrogate `id uuid` primary key (gen_random_uuid());
--   * every table has `created_at` — when the row was inserted;
--   * the database is the only time source: timestamps default to now()
--     and auth-lib passes durations, never instants;
--   * all timestamps are `timestamptz` (stored as UTC instants; the adapter
--     also pins each connection's TimeZone to UTC);
--   * closed value sets are ENUM types.

-- ── Enum types ────────────────────────────────────────────────────────────────
-- Adding a value later: ALTER TYPE ... ADD VALUE '...' in a new migration.
-- Values can't be removed or reordered without recreating the type.

CREATE TYPE session_status AS ENUM ('active', 'revoked', 'compromised');

CREATE TYPE revocation_scope AS ENUM ('session', 'user');

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
    'account_deleted'
);

-- ── roles ─────────────────────────────────────────────────────────────────────
-- Immutable once created (no update API), so no updated_at.
CREATE TABLE "roles" (
    "id"          uuid         NOT NULL DEFAULT gen_random_uuid(),
    "name"        varchar(50)  NOT NULL,
    "description" text,
    "created_at"  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX roles_name_key ON public.roles USING btree (name);

-- ── users ─────────────────────────────────────────────────────────────────────
-- The only table with free-form edits, hence the only one with updated_at
-- (set explicitly by every UPDATE query — no trigger overhead).
CREATE TABLE "users" (
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

-- Case-insensitive uniqueness.  Emails are lowercased by auth-lib before
-- they reach the database; usernames keep their display case, so lookups
-- compare lower(username) = lower($1).
CREATE UNIQUE INDEX users_email        ON public.users USING btree (lower(email));
CREATE UNIQUE INDEX users_username_key ON public.users USING btree (lower(username));

-- ── users_roles ───────────────────────────────────────────────────────────────
-- revoked_at is NULL while the assignment is active; set to the revocation
-- timestamp when the role is withdrawn.  This keeps the full audit trail
-- without a separate history table.  assigned_at is the business event;
-- created_at is row bookkeeping (equal today, independent by design).
CREATE TABLE "users_roles" (
    "id"          uuid        NOT NULL DEFAULT gen_random_uuid(),
    "user_id"     uuid        NOT NULL,
    "role_id"     uuid        NOT NULL,
    "assigned_at" timestamptz NOT NULL DEFAULT now(),
    "revoked_at"  timestamptz,                         -- NULL → active
    "created_at"  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_users_roles_user_id
        FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
    CONSTRAINT fk_users_roles_role_id
        FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE CASCADE,
    CONSTRAINT chk_users_roles_revoked_after_assigned
        CHECK ("revoked_at" IS NULL OR "revoked_at" >= "assigned_at")
);

-- Uniqueness is scoped to *active* assignments only: the same (user, role)
-- pair may appear multiple times historically, but only once with
-- revoked_at IS NULL.
CREATE UNIQUE INDEX unique_user_role_active
    ON public.users_roles (user_id, role_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_users_roles_user_id
    ON public.users_roles USING btree (user_id);

CREATE INDEX idx_users_roles_role_id
    ON public.users_roles USING btree (role_id);

-- Partial index: fast lookup of every active assignment for a user.
CREATE INDEX idx_users_roles_active
    ON public.users_roles (user_id, assigned_at DESC)
    WHERE revoked_at IS NULL;

-- Partial index: fast lookup of revoked assignments (audit / reporting).
CREATE INDEX idx_users_roles_removed
    ON public.users_roles (user_id, revoked_at DESC)
    WHERE revoked_at IS NOT NULL;

-- ── sessions ──────────────────────────────────────────────────────────────────
-- One row per login on one device.  No token material is stored: refresh
-- tokens are re-derived from (id, generation, secret) plus the server-wide
-- refresh key, and access tokens are identified by their jti only.
-- Every change is captured by a dedicated column (current_generation,
-- idle_expires_at, status/end_reason/ended_at), so no updated_at.
CREATE TABLE "sessions" (
    "id"                  uuid              NOT NULL DEFAULT gen_random_uuid(),
    "user_id"             uuid              NOT NULL,
    "secret"              bytea             NOT NULL,   -- mixed into refresh-token MACs
    "status"              session_status    NOT NULL DEFAULT 'active',
    "end_reason"          revocation_reason,            -- set when ended
    "created_ip"          inet              NOT NULL,
    "user_agent"          varchar(512),                 -- truncated by auth-lib
    "current_generation"  integer           NOT NULL DEFAULT 1,
    "created_at"          timestamptz       NOT NULL DEFAULT now(),
    "idle_expires_at"     timestamptz       NOT NULL,   -- pushed forward on every refresh
    "absolute_expires_at" timestamptz       NOT NULL,   -- hard cap
    "ended_at"            timestamptz,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_sessions_user_id
        FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
    CONSTRAINT chk_sessions_generation_positive
        CHECK ("current_generation" >= 1),
    -- Active ⇔ not ended: an ended session always has both a time and a reason.
    CONSTRAINT chk_sessions_ended
        CHECK ((("status" = 'active') = ("ended_at" IS NULL))
           AND (("status" = 'active') = ("end_reason" IS NULL)))
);

-- Active sessions per user, oldest first (session cap, logout-all).
-- Partial, so ended sessions awaiting purge don't bloat it.
CREATE INDEX idx_sessions_user_active
    ON public.sessions (user_id, created_at)
    WHERE status = 'active';

-- Housekeeping: the moment a session became purgeable.  The purge query
-- must repeat this expression verbatim to use the index.
CREATE INDEX idx_sessions_purge
    ON public.sessions (LEAST(idle_expires_at, absolute_expires_at,
                              COALESCE(ended_at, 'infinity')));

-- ── session_generations ───────────────────────────────────────────────────────
-- Token rotation history: the newest N generations of each session are kept
-- for reuse detection (N = session history size, default 10).
-- The row's id doubles as the access token's jti.
CREATE TABLE "session_generations" (
    "id"                uuid        NOT NULL DEFAULT gen_random_uuid(),  -- = access-token jti
    "session_id"        uuid        NOT NULL,
    "generation"        integer     NOT NULL,
    "issued_ip"         inet        NOT NULL,
    "issued_at"         timestamptz NOT NULL DEFAULT now(),
    "access_expires_at" timestamptz NOT NULL,
    "superseded_at"     timestamptz,                     -- set when generation + 1 is issued
    "created_at"        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_session_generations_session_id
        FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE,
    CONSTRAINT session_generations_session_generation_key
        UNIQUE ("session_id", "generation"),
    CONSTRAINT chk_session_generations_positive
        CHECK ("generation" >= 1)
);

-- ── revocations ───────────────────────────────────────────────────────────────
-- Persisted denylist, append-only.  Every server periodically loads the
-- unexpired rows into memory.  A row only needs to live for the access-token
-- TTL + leeway, so the table stays small.
CREATE TABLE "revocations" (
    "id"         uuid              NOT NULL DEFAULT gen_random_uuid(),
    "scope"      revocation_scope  NOT NULL,
    "subject"    uuid              NOT NULL,             -- session id | user id
    "reason"     revocation_reason NOT NULL,
    "revoked_at" timestamptz       NOT NULL DEFAULT now(),
    "expires_at" timestamptz       NOT NULL,
    "created_at" timestamptz       NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);

-- list_active() and purge_expired().
CREATE INDEX idx_revocations_expires_at
    ON public.revocations USING btree (expires_at);
