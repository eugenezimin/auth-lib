-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: auth_lib
-- Generation Time: 2026-04-11 09:23:59.1900
-- -------------------------------------------------------------


DROP TABLE IF EXISTS "public"."sessions";
-- Table Definition
CREATE TABLE "public"."sessions" (
    "id" uuid NOT NULL DEFAULT gen_random_uuid(),
    "user_id" uuid NOT NULL,
    "access_token" text NOT NULL,
    "access_created_at" timestamptz NOT NULL,
    "access_expires_at" timestamptz NOT NULL,
    "refresh_token" text NOT NULL,
    "refresh_created_at" timestamptz NOT NULL,
    "refresh_expires_at" timestamptz NOT NULL,
    PRIMARY KEY ("id")
);

DROP TABLE IF EXISTS "public"."users";
-- Table Definition
CREATE TABLE "public"."users" (
    "id" uuid NOT NULL DEFAULT gen_random_uuid(),
    "email" varchar(255) NOT NULL,
    "password_hash" text,
    "jwt_secret" text,
    "username" varchar(100),
    "first_name" varchar(255),
    "last_name" varchar(255),
    "avatar_url" text,
    "is_active" bool NOT NULL DEFAULT true,
    "is_verified" bool NOT NULL DEFAULT false,
    "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("id")
);

DROP TABLE IF EXISTS "public"."user_roles";
-- Table Definition
CREATE TABLE "public"."user_roles" (
    "id" uuid NOT NULL DEFAULT gen_random_uuid(),
    "user_id" uuid NOT NULL,
    "role_id" uuid NOT NULL,
    "assigned_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("id")
);

DROP TABLE IF EXISTS "public"."roles";
-- Table Definition
CREATE TABLE "public"."roles" (
    "id" uuid NOT NULL DEFAULT gen_random_uuid(),
    "name" varchar(50) NOT NULL,
    "description" text,
    "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("id")
);

ALTER TABLE "public"."sessions" ADD FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;


-- Indices
CREATE INDEX idx_sessions_user_id ON public.sessions USING btree (user_id);
CREATE INDEX idx_sessions_access_token ON public.sessions USING btree (access_token);
CREATE INDEX idx_sessions_refresh_token ON public.sessions USING btree (refresh_token);
CREATE INDEX idx_sessions_user_id_expires ON public.sessions USING btree (user_id, access_expires_at DESC);


-- Indices
CREATE UNIQUE INDEX users_username_key ON public.users USING btree (username);
CREATE UNIQUE INDEX users_email ON public.users USING btree (email);
ALTER TABLE "public"."user_roles" ADD FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;
ALTER TABLE "public"."user_roles" ADD FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX pk_user_roles ON public.user_roles USING btree (id);
CREATE UNIQUE INDEX unique_user_role ON public.user_roles USING btree (user_id, role_id);
CREATE INDEX idx_user_roles_user_id ON public.user_roles USING btree (user_id);
CREATE INDEX idx_user_roles_role_id ON public.user_roles USING btree (role_id);


-- Indices
CREATE UNIQUE INDEX roles_name_key ON public.roles USING btree (name);
