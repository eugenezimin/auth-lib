-- -------------------------------------------------------------
-- Migration 0002 — authorization: role codes and the permission catalog
-- -------------------------------------------------------------
--
-- Same conventions as 0001: uuid primary keys, `created_at` everywhere,
-- database-assigned time, ENUMs for closed sets.  Grant rows are replaced,
-- never edited, so there is no `updated_at`.
--
-- Permissions are encoded into access tokens by *position*: every `bool`
-- and `text` permission and every option of a `single` / `multi`
-- permission takes a number from `permission_position_seq`.  Positions are
-- permanent and never reused, so tokens and cached catalogs stay decodable
-- across catalog changes (see docs/authorization.md).

-- ── roles.code ────────────────────────────────────────────────────────────────
-- Immutable identifier carried in tokens (`rol`).  Existing roles get a
-- code derived from their name.
ALTER TABLE "roles" ADD COLUMN "code" varchar(64);

UPDATE "roles"
SET "code" = trim(BOTH '_' FROM lower(regexp_replace("name", '[^a-zA-Z0-9]+', '_', 'g')));

UPDATE "roles" SET "code" = 'role_' || "code" WHERE "code" !~ '^[a-z]';

ALTER TABLE "roles" ALTER COLUMN "code" SET NOT NULL;

ALTER TABLE "roles" ADD CONSTRAINT chk_roles_code_format
    CHECK ("code" ~ '^[a-z][a-z0-9_.:-]*$');

CREATE UNIQUE INDEX roles_code_key ON public.roles USING btree (code);

-- ── permission catalog ────────────────────────────────────────────────────────

CREATE TYPE permission_kind AS ENUM ('bool', 'single', 'multi', 'text');

CREATE SEQUENCE permission_position_seq AS integer START 1;

CREATE TABLE "permissions" (
    "id"          uuid            NOT NULL DEFAULT gen_random_uuid(),
    "code"        varchar(64)     NOT NULL,
    "kind"        permission_kind NOT NULL,
    "description" text,
    "position"    integer,                     -- bool / text only
    "max_length"  integer,                     -- text only
    "created_at"  timestamptz     NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT chk_permissions_code_format
        CHECK ("code" ~ '^[a-z][a-z0-9_.:-]*$'),
    CONSTRAINT chk_permissions_position
        CHECK (("kind" IN ('bool', 'text')) = ("position" IS NOT NULL)),
    CONSTRAINT chk_permissions_max_length
        CHECK (("kind" = 'text') = ("max_length" IS NOT NULL) AND
               ("max_length" IS NULL OR "max_length" > 0))
);

CREATE UNIQUE INDEX permissions_code_key     ON public.permissions USING btree (code);
CREATE UNIQUE INDEX permissions_position_key ON public.permissions USING btree (position);

CREATE TABLE "permission_options" (
    "id"            uuid        NOT NULL DEFAULT gen_random_uuid(),
    "permission_id" uuid        NOT NULL,
    "code"          varchar(64) NOT NULL,
    "position"      integer     NOT NULL DEFAULT nextval('permission_position_seq'),
    "created_at"    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_permission_options_permission_id
        FOREIGN KEY ("permission_id") REFERENCES "permissions"("id") ON DELETE CASCADE,
    CONSTRAINT permission_options_permission_code_key
        UNIQUE ("permission_id", "code"),
    CONSTRAINT chk_permission_options_code_format
        CHECK ("code" ~ '^[a-z][a-z0-9_.:-]*$')
);

CREATE UNIQUE INDEX permission_options_position_key
    ON public.permission_options USING btree (position);

-- ── grants ────────────────────────────────────────────────────────────────────
-- One row per granted `bool` / `text` permission (option_id NULL) or per
-- chosen option.  Kind consistency (which column is set) is enforced by
-- auth-lib's PermissionService.

CREATE TABLE "user_permission_grants" (
    "id"            uuid        NOT NULL DEFAULT gen_random_uuid(),
    "user_id"       uuid        NOT NULL,
    "permission_id" uuid        NOT NULL,
    "option_id"     uuid,
    "text_value"    text,
    "created_at"    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_user_permission_grants_user_id
        FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
    CONSTRAINT fk_user_permission_grants_permission_id
        FOREIGN KEY ("permission_id") REFERENCES "permissions"("id") ON DELETE CASCADE,
    CONSTRAINT fk_user_permission_grants_option_id
        FOREIGN KEY ("option_id") REFERENCES "permission_options"("id") ON DELETE CASCADE,
    CONSTRAINT chk_user_permission_grants_shape
        CHECK ("option_id" IS NULL OR "text_value" IS NULL)
);

CREATE UNIQUE INDEX user_permission_grants_value_key
    ON public.user_permission_grants (user_id, permission_id) WHERE option_id IS NULL;
CREATE UNIQUE INDEX user_permission_grants_option_key
    ON public.user_permission_grants (user_id, option_id) WHERE option_id IS NOT NULL;

CREATE TABLE "role_permission_grants" (
    "id"            uuid        NOT NULL DEFAULT gen_random_uuid(),
    "role_id"       uuid        NOT NULL,
    "permission_id" uuid        NOT NULL,
    "option_id"     uuid,
    "text_value"    text,
    "created_at"    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY ("id"),
    CONSTRAINT fk_role_permission_grants_role_id
        FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_grants_permission_id
        FOREIGN KEY ("permission_id") REFERENCES "permissions"("id") ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_grants_option_id
        FOREIGN KEY ("option_id") REFERENCES "permission_options"("id") ON DELETE CASCADE,
    CONSTRAINT chk_role_permission_grants_shape
        CHECK ("option_id" IS NULL OR "text_value" IS NULL)
);

CREATE UNIQUE INDEX role_permission_grants_value_key
    ON public.role_permission_grants (role_id, permission_id) WHERE option_id IS NULL;
CREATE UNIQUE INDEX role_permission_grants_option_key
    ON public.role_permission_grants (role_id, option_id) WHERE option_id IS NOT NULL;

-- Login / refresh read a user's grants (direct, and via roles).
CREATE INDEX idx_user_permission_grants_user_id
    ON public.user_permission_grants USING btree (user_id);
CREATE INDEX idx_role_permission_grants_role_id
    ON public.role_permission_grants USING btree (role_id);
