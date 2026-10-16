-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: z_auth
-- Migration 3001 — external identities and flow states
--                  (feature `external-identity`)
-- -------------------------------------------------------------
--
-- Applied by `z_auth_postgres::EXTERNAL_MIGRATOR`, after the core set
-- (`migrations/`).  Versions start at 3001 so they never collide with the
-- core (< 1000), cluster (1001–1999) or mfa (2001–2999) sets, which share
-- `_sqlx_migrations`.  Never edit this file once applied anywhere — add
-- `3002_<description>.sql` instead.
--
-- Neither table is in the cluster change feed: external sign-in and
-- linking happen at the authority only.

-- ── identity_external_identities ──────────────────────────────────────────────
-- Identities of other providers (OIDC, OAuth2, …) linked to a user.  A user
-- may have many; an (issuer, subject) pair belongs to one user.  `provider`
-- is the host's name for the provider configuration; `email` is what the
-- provider reported when the identity was linked.
CREATE TABLE "identity_external_identities" (
    "id"            uuid         NOT NULL DEFAULT gen_random_uuid(),
    "user_id"       uuid         NOT NULL,
    "provider"      varchar(64)  NOT NULL,
    "issuer"        text         NOT NULL,
    "subject"       text         NOT NULL,
    "email"         varchar(255),
    "created_at"    timestamptz  NOT NULL DEFAULT now(),
    "last_login_at" timestamptz,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_identity_external_identities_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT uq_identity_external_identities_subject UNIQUE ("issuer", "subject")
);

CREATE INDEX identity_external_identities_user_id
    ON identity_external_identities USING btree (user_id, created_at);

-- ── security_flow_states ──────────────────────────────────────────────────────
-- Single-use state of multi-step sign-ins (a sign-in waiting for the local
-- password, an external login waiting for a second factor, a redirect to an
-- identity provider).  Keys are `kind:` plus a SHA-256 of the client's
-- token, never the token itself.  Rows past `expires_at` are dead and
-- purged by `ZAuth::tick`.
CREATE TABLE "security_flow_states" (
    "key"        varchar(255) NOT NULL,
    "value"      text         NOT NULL,
    "expires_at" timestamptz  NOT NULL,
    PRIMARY KEY ("key")
);

CREATE INDEX security_flow_states_expires_at
    ON security_flow_states USING btree (expires_at);
