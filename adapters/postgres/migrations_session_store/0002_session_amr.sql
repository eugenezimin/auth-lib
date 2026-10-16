-- -------------------------------------------------------------
-- Session store migration 0002 — authentication methods on sessions
-- -------------------------------------------------------------
--
-- * security_sessions.amr: the RFC 8176 authentication methods a session
--   was opened with (sorted, e.g. {mfa,otp,pwd}); carried by every access
--   token the session issues.  Sessions that predate it were opened with a
--   password.  A constant default needs no table rewrite, and no UPDATE
--   runs, so the change-feed triggers do not fire for existing sessions.
-- * revocation_reason gains second_factor_changed (z-auth-mfa ends a
--   user's sessions when their second factors change).

ALTER TABLE security_sessions ADD COLUMN "amr" text[] NOT NULL DEFAULT '{pwd}';

ALTER TYPE revocation_reason ADD VALUE 'second_factor_changed';
