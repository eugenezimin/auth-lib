-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: z_auth
-- Migration 2001 — two-factor schema (z-auth-mfa, feature `mfa`)
-- -------------------------------------------------------------
--
-- Applied by `z_auth_postgres::MFA_MIGRATOR`, after the core set
-- (`migrations/`).  Versions start at 2001 so they never collide with the
-- core (< 1000) or cluster (1001–1999) sets, which share
-- `_sqlx_migrations`.  Never edit this file once applied anywhere — add
-- `2002_<description>.sql` instead.
--
-- Nothing secret is stored in clear: TOTP secrets and email / SMS
-- destinations are sealed by z-auth-mfa (XChaCha20-Poly1305, bound to the
-- user and factor ids); codes, recovery codes and challenge secrets are
-- HMAC-SHA256 under AUTH_MFA_HASH_KEY.  Every row belongs to an
-- identity_users row and goes with it.  No table is in the cluster change
-- feed: second factors live on the authority only.

CREATE TYPE mfa_method         AS ENUM ('totp', 'email', 'sms');
CREATE TYPE mfa_factor_status  AS ENUM ('pending', 'active');
CREATE TYPE mfa_totp_algorithm AS ENUM ('sha1', 'sha256', 'sha512');

-- ── mfa_factors ───────────────────────────────────────────────────────────────
-- One enrolled (active) or enrolling (pending, expires) factor:
--
--   pending ──first code──► active ──removed──► (row deleted)
--      └──expires──► purged
--
-- At most one active and one pending factor per user and method.  `code_*`
-- hold the email / SMS code sent to confirm an enrollment or for a step-up
-- proof.  `last_used_step` makes each TOTP time step usable once.
CREATE TABLE "mfa_factors" (
    "id"                 uuid               NOT NULL,   -- chosen by z-auth-mfa
    "user_id"            uuid               NOT NULL,
    "method"             mfa_method         NOT NULL,
    "status"             mfa_factor_status  NOT NULL DEFAULT 'pending',
    "label"              varchar(64),
    "secret_sealed"      bytea,                         -- TOTP
    "totp_algorithm"     mfa_totp_algorithm,            -- TOTP
    "totp_digits"        smallint,                      -- TOTP
    "totp_period_secs"   integer,                       -- TOTP
    "last_used_step"     bigint,                        -- TOTP
    "destination_sealed" bytea,                         -- email / SMS
    "destination_hint"   varchar(64),                   -- email / SMS, masked
    "code_hash"          bytea,
    "code_expires_at"    timestamptz,
    "code_sent_at"       timestamptz,
    "code_sends"         integer            NOT NULL DEFAULT 0,
    "code_attempts"      integer            NOT NULL DEFAULT 0,
    "created_at"         timestamptz        NOT NULL DEFAULT now(),
    "expires_at"         timestamptz,                   -- pending only
    "confirmed_at"       timestamptz,                   -- active only
    "last_used_at"       timestamptz,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_mfa_factors_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT chk_mfa_factors_totp
        CHECK (("method" = 'totp') = ("secret_sealed" IS NOT NULL
                                      AND "totp_algorithm" IS NOT NULL
                                      AND "totp_digits" IS NOT NULL
                                      AND "totp_period_secs" IS NOT NULL)),
    CONSTRAINT chk_mfa_factors_destination
        CHECK (("method" = 'totp') = ("destination_sealed" IS NULL)),
    CONSTRAINT chk_mfa_factors_pending
        CHECK (("status" = 'pending') = ("expires_at" IS NOT NULL)),
    CONSTRAINT chk_mfa_factors_active
        CHECK (("status" = 'active') = ("confirmed_at" IS NOT NULL)),
    CONSTRAINT chk_mfa_factors_code
        CHECK ("code_hash" IS NULL
               OR (octet_length("code_hash") = 32
                   AND "code_expires_at" IS NOT NULL
                   AND "code_sent_at" IS NOT NULL))
);

CREATE UNIQUE INDEX uq_mfa_factors_user_method_active
    ON mfa_factors (user_id, method) WHERE status = 'active';
CREATE UNIQUE INDEX uq_mfa_factors_user_method_pending
    ON mfa_factors (user_id, method) WHERE status = 'pending';
CREATE INDEX idx_mfa_factors_user
    ON mfa_factors (user_id, created_at);
-- Purge of expired enrollments.
CREATE INDEX idx_mfa_factors_pending_expiry
    ON mfa_factors (expires_at) WHERE status = 'pending';

-- ── mfa_recovery_codes ────────────────────────────────────────────────────────
-- Single-use codes, replaced as a set.
CREATE TABLE "mfa_recovery_codes" (
    "id"         uuid         NOT NULL DEFAULT gen_random_uuid(),
    "user_id"    uuid         NOT NULL,
    "code_hash"  bytea        NOT NULL,
    "created_at" timestamptz  NOT NULL DEFAULT now(),
    "used_at"    timestamptz,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_mfa_recovery_codes_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT uq_mfa_recovery_codes_user_code UNIQUE ("user_id", "code_hash"),
    CONSTRAINT chk_mfa_recovery_codes_hash CHECK (octet_length("code_hash") = 32)
);

-- ── mfa_challenges ────────────────────────────────────────────────────────────
-- A login that passed the password step and waits for its second factor.
-- Bounded attempts, single use (`consumed_at`), and the email / SMS code
-- sent for it (`code_*`, through factor `code_factor_id`).
CREATE TABLE "mfa_challenges" (
    "id"               uuid         NOT NULL,
    "user_id"          uuid         NOT NULL,
    "secret_hash"      bytea        NOT NULL,
    "created_ip"       inet         NOT NULL,
    "user_agent"       varchar(512),
    "fingerprint_hash" bytea,
    "attempts"         integer      NOT NULL DEFAULT 0,
    "created_at"       timestamptz  NOT NULL DEFAULT now(),
    "expires_at"       timestamptz  NOT NULL,
    "consumed_at"      timestamptz,
    "code_factor_id"   uuid,
    "code_hash"        bytea,
    "code_expires_at"  timestamptz,
    "code_sent_at"     timestamptz,
    "code_sends"       integer      NOT NULL DEFAULT 0,
    "code_attempts"    integer      NOT NULL DEFAULT 0,
    PRIMARY KEY ("id"),
    CONSTRAINT fk_mfa_challenges_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT chk_mfa_challenges_secret CHECK (octet_length("secret_hash") = 32),
    CONSTRAINT chk_mfa_challenges_fingerprint
        CHECK ("fingerprint_hash" IS NULL OR octet_length("fingerprint_hash") = 32),
    CONSTRAINT chk_mfa_challenges_code
        CHECK ("code_hash" IS NULL
               OR (octet_length("code_hash") = 32
                   AND "code_factor_id" IS NOT NULL
                   AND "code_expires_at" IS NOT NULL
                   AND "code_sent_at" IS NOT NULL))
);

-- Purge of expired challenges.
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);

-- ── mfa_user_state ────────────────────────────────────────────────────────────
-- Failed second-factor attempts per user, for the lockout.  A row exists
-- only while there is something to remember.
CREATE TABLE "mfa_user_state" (
    "user_id"           uuid         NOT NULL,
    "failures"          integer      NOT NULL DEFAULT 0,
    "window_started_at" timestamptz  NOT NULL DEFAULT now(),
    "locked_until"      timestamptz,
    PRIMARY KEY ("user_id"),
    CONSTRAINT fk_mfa_user_state_user_id
        FOREIGN KEY ("user_id") REFERENCES "identity_users" ("id") ON DELETE CASCADE
);
