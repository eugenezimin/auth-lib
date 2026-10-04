-- -------------------------------------------------------------
-- Migration 0003 — cluster sync: revocation status, node registry,
-- published verifying keys
-- -------------------------------------------------------------
--
-- Same conventions as before: uuid primary keys, `created_at` everywhere,
-- database-assigned time, ENUMs for closed sets.
--
-- None of these tables is read on token verification.  They are written
-- when something changes and read once at startup; between instances,
-- changes travel as pushed messages (see docs/cluster.md).

-- A token covered by a pending revocation was presented: the session is
-- marked compromised with this reason.  (Not used in this migration, so
-- adding it inside the migration's transaction is fine.)
ALTER TYPE revocation_reason ADD VALUE 'revoked_token_used';

-- ── revocations: pending → enforced ───────────────────────────────────────────
CREATE TYPE revocation_status AS ENUM ('pending', 'enforced');

ALTER TABLE "revocations"
    ADD COLUMN "status"      revocation_status NOT NULL DEFAULT 'pending',
    -- The instance that issued it.  Rows from before this migration have none.
    ADD COLUMN "origin_node" uuid,
    ADD COLUMN "enforced_at" timestamptz,
    ADD COLUMN "enforced_by" uuid,
    ADD CONSTRAINT chk_revocations_enforced
        CHECK (("status" = 'enforced') = ("enforced_at" IS NOT NULL));

-- ── cluster_nodes: the registry instances read at startup ────────────────────
CREATE TYPE node_status AS ENUM ('up', 'down', 'left');

CREATE TABLE "cluster_nodes" (
    "id"           uuid         NOT NULL,              -- node id, generated per process start
    "service"      varchar(100) NOT NULL,
    "ip"           inet,
    "dns_name"     varchar(253),
    "port"         integer      NOT NULL,
    "version"      varchar(32)  NOT NULL,
    "status"       node_status  NOT NULL DEFAULT 'up',
    "started_at"   timestamptz  NOT NULL,
    "last_seen_at" timestamptz,
    "created_at"   timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT chk_cluster_nodes_port CHECK ("port" BETWEEN 1 AND 65535),
    CONSTRAINT chk_cluster_nodes_address CHECK ("ip" IS NOT NULL OR "dns_name" IS NOT NULL)
);

-- Startup reads the nodes that are up.
CREATE INDEX idx_cluster_nodes_up ON public.cluster_nodes (service) WHERE status = 'up';

-- ── verifying_keys: public keys published by instances ───────────────────────
-- Only public Ed25519 keys; private keys never leave their instance.
CREATE TYPE verifying_key_status AS ENUM ('active', 'revoked');

CREATE TABLE "verifying_keys" (
    "id"           uuid                 NOT NULL DEFAULT gen_random_uuid(),
    "kid"          varchar(32)          NOT NULL,      -- JWT key id
    "public_key"   bytea                NOT NULL,
    "status"       verifying_key_status NOT NULL DEFAULT 'active',
    "published_by" uuid,
    "revoked_at"   timestamptz,
    "created_at"   timestamptz          NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT chk_verifying_keys_length CHECK (octet_length("public_key") = 32),
    CONSTRAINT chk_verifying_keys_revoked
        CHECK (("status" = 'revoked') = ("revoked_at" IS NOT NULL))
);

CREATE UNIQUE INDEX verifying_keys_kid_key ON public.verifying_keys USING btree (kid);
