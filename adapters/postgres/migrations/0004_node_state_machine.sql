-- -------------------------------------------------------------
-- Migration 0004 — cluster_nodes becomes a state machine
-- -------------------------------------------------------------
--
-- Two independent dimensions per node, each changed only by its events:
--
--   state      joining ──► active ──► leaving ──► (row deleted)
--   heartbeat  online ──missed──► offline ──still silent──► (row deleted)
--                 ▲                  │
--                 └──── heard ───────┘
--
-- Every change is a guarded, idempotent write (`… WHERE state = 'joining'`,
-- `… WHERE heartbeat = 'online'`, …), so when several instances observe the
-- same event exactly one changes the row.  Steady-state heartbeats never
-- write here.

CREATE TYPE node_state       AS ENUM ('joining', 'active', 'leaving');
CREATE TYPE heartbeat_status AS ENUM ('online', 'offline');

-- Rows of nodes that went down or left under the old scheme describe
-- processes that are gone; the rest are treated as active and online (any
-- that are actually dead go offline and are removed by the first observer).
DELETE FROM "cluster_nodes" WHERE "status" <> 'up';

ALTER TABLE "cluster_nodes"
    ADD COLUMN "state"                node_state       NOT NULL DEFAULT 'active',
    ADD COLUMN "heartbeat"            heartbeat_status NOT NULL DEFAULT 'online',
    ADD COLUMN "state_changed_at"     timestamptz      NOT NULL DEFAULT now(),
    ADD COLUMN "heartbeat_changed_at" timestamptz      NOT NULL DEFAULT now();

ALTER TABLE "cluster_nodes" ALTER COLUMN "state" SET DEFAULT 'joining';

-- Replaced by the two columns above; `last_seen_at` would have to be
-- written on every heartbeat.
DROP INDEX IF EXISTS idx_cluster_nodes_up;
ALTER TABLE "cluster_nodes" DROP COLUMN "status", DROP COLUMN "last_seen_at";
DROP TYPE node_status;
