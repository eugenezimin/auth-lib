-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: auth_lib
-- Generation Time: 2026-04-13
-- -------------------------------------------------------------

DROP TABLE IF EXISTS "sessions"   CASCADE;
DROP TABLE IF EXISTS "users_roles" CASCADE;
DROP TABLE IF EXISTS "users"      CASCADE;
DROP TABLE IF EXISTS "roles"      CASCADE;

-- ── roles ─────────────────────────────────────────────────────────────────────
CREATE TABLE "roles" (
    "id"          uuid         NOT NULL DEFAULT gen_random_uuid(),
    "name"        varchar(50)  NOT NULL,
    "description" text,
    "created_at"  timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX roles_name_key ON public.roles USING btree (name);

-- ── users ─────────────────────────────────────────────────────────────────────
CREATE TABLE "users" (
    "id"            uuid         NOT NULL DEFAULT gen_random_uuid(),
    "email"         varchar(255) NOT NULL,
    "password_hash" text,
    "jwt_secret"    text,
    "username"      varchar(100),
    "first_name"    varchar(255),
    "last_name"     varchar(255),
    "avatar_url"    text,
    "is_active"     bool         NOT NULL DEFAULT true,
    "is_verified"   bool         NOT NULL DEFAULT false,
    "created_at"    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX users_email        ON public.users USING btree (email);
CREATE UNIQUE INDEX users_username_key ON public.users USING btree (username);

-- ── users_roles ────────────────────────────────────────────────────────────────
-- revoked_at is NULL while the assignment is active; set to the revocation
-- timestamp when the role is withdrawn.  This keeps the full audit trail
-- without a separate history table.
CREATE TABLE "users_roles" (
    "id"          uuid        NOT NULL DEFAULT gen_random_uuid(),
    "user_id"     uuid        NOT NULL,
    "role_id"     uuid        NOT NULL,
    "assigned_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked_at"  timestamptz,                         -- NULL  → active
    PRIMARY KEY ("id"),
    CONSTRAINT fk_users_roles_user_id
        FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
    CONSTRAINT fk_users_roles_role_id
        FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE CASCADE
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
CREATE TABLE "sessions" (
    "id"                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    "user_id"            uuid        NOT NULL,
    "access_token"       text        NOT NULL,
    "access_created_at"  timestamptz NOT NULL,
    "access_expires_at"  timestamptz NOT NULL,
    "refresh_token"      text        NOT NULL,
    "refresh_created_at" timestamptz NOT NULL,
    "refresh_expires_at" timestamptz NOT NULL,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_sessions_user_id
        FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user_id
    ON public.sessions USING btree (user_id);

-- Token lookups need to be fast; prefix length not required for btree on text.
CREATE INDEX idx_sessions_access_token
    ON public.sessions USING btree (access_token);

CREATE INDEX idx_sessions_refresh_token
    ON public.sessions USING btree (refresh_token);

-- Composite index used by "get the newest active session for a user" queries.
CREATE INDEX idx_sessions_user_id_expires
    ON public.sessions USING btree (user_id, access_expires_at DESC);