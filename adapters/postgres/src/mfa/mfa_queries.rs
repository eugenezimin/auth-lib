//! SQL for the `mfa_` tables (see `migrations_mfa/2001_mfa_schema.sql`).
//!
//! Every timestamp comes from `now()`; callers bind durations.  Every
//! compare-and-swap is one guarded `UPDATE … WHERE …`, so concurrent callers
//! serialise on the row lock and at most one succeeds.

// ── mfa_factors ───────────────────────────────────────────────────────────────

macro_rules! factor_columns {
    () => {
        "id, user_id, method, status, label, secret_sealed, totp_algorithm, \
         totp_digits, totp_period_secs, last_used_step, destination_sealed, destination_hint, \
         code_hash, code_expires_at, code_sent_at, code_sends, code_attempts, created_at, \
         expires_at, confirmed_at, last_used_at"
    };
}

pub const LIST_FACTORS: &str = concat!(
    "SELECT ",
    factor_columns!(),
    ", now() AS db_now FROM mfa_factors WHERE user_id = $1 ORDER BY created_at, id"
);

pub const FIND_FACTOR: &str = concat!(
    "SELECT ",
    factor_columns!(),
    ", now() AS db_now FROM mfa_factors WHERE id = $1"
);

pub const DELETE_PENDING_FACTOR: &str =
    "DELETE FROM mfa_factors WHERE user_id = $1 AND method = $2 AND status = 'pending'";

pub const INSERT_PENDING_FACTOR: &str = concat!(
    "INSERT INTO mfa_factors (id, user_id, method, label, secret_sealed, totp_algorithm, \
     totp_digits, totp_period_secs, destination_sealed, destination_hint, expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now() + $11) RETURNING ",
    factor_columns!(),
    ", now() AS db_now"
);

/// Pending and unexpired → active.  A second active factor of the method
/// violates `uq_mfa_factors_user_method_active`.
pub const ACTIVATE_FACTOR: &str = r#"
    UPDATE mfa_factors
    SET status = 'active', confirmed_at = now(), expires_at = NULL, last_used_step = $3,
        code_hash = NULL, code_expires_at = NULL, code_sent_at = NULL,
        code_sends = 0, code_attempts = 0
    WHERE id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > now()
"#;

pub const DELETE_FACTOR: &str = "DELETE FROM mfa_factors WHERE id = $1 AND user_id = $2";

pub const ADVANCE_TOTP_STEP: &str = r#"
    UPDATE mfa_factors
    SET last_used_step = $2, last_used_at = now()
    WHERE id = $1 AND (last_used_step IS NULL OR last_used_step < $2)
"#;

pub const MARK_FACTOR_USED: &str = r#"
    UPDATE mfa_factors
    SET last_used_at = now(), code_hash = NULL, code_expires_at = NULL, code_sent_at = NULL,
        code_sends = 0, code_attempts = 0
    WHERE id = $1
"#;

/// `$2` hash, `$3` ttl, `$4` resend_after, `$5` max_sends.  Sends count up
/// while the previous code is valid and restart once it expired.
pub const SET_FACTOR_CODE: &str = r#"
    UPDATE mfa_factors
    SET code_sends = CASE WHEN code_hash IS NOT NULL AND code_expires_at > now()
                          THEN code_sends + 1 ELSE 1 END,
        code_hash = $2, code_expires_at = now() + $3, code_sent_at = now(), code_attempts = 0
    WHERE id = $1
      AND (status = 'active' OR expires_at > now())
      AND (code_sent_at IS NULL OR code_sent_at + $4 <= now())
      AND NOT (code_hash IS NOT NULL AND code_expires_at > now() AND code_sends >= $5)
    RETURNING code_expires_at
"#;

/// Why `SET_FACTOR_CODE` stored nothing.
pub const FACTOR_CODE_REFUSAL: &str = r#"
    SELECT (status = 'active' OR expires_at > now()) AS usable,
           (code_sent_at IS NOT NULL AND code_sent_at + $2 > now()) AS too_soon
    FROM mfa_factors WHERE id = $1
"#;

pub const RECORD_FACTOR_ATTEMPT: &str = r#"
    UPDATE mfa_factors
    SET code_attempts = code_attempts + 1
    WHERE id = $1 AND code_hash IS NOT NULL AND code_expires_at > now() AND code_attempts < $2
    RETURNING code_attempts
"#;

// ── mfa_recovery_codes ────────────────────────────────────────────────────────

pub const DELETE_RECOVERY_CODES: &str = "DELETE FROM mfa_recovery_codes WHERE user_id = $1";

pub const INSERT_RECOVERY_CODES: &str = r#"
    INSERT INTO mfa_recovery_codes (user_id, code_hash)
    SELECT $1, h FROM unnest($2::bytea[]) AS h
"#;

pub const CONSUME_RECOVERY_CODE: &str = r#"
    UPDATE mfa_recovery_codes
    SET used_at = now()
    WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
"#;

pub const COUNT_RECOVERY_CODES: &str =
    "SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL";

// ── mfa_challenges ────────────────────────────────────────────────────────────

macro_rules! challenge_columns {
    () => {
        "id, user_id, secret_hash, created_ip, user_agent, fingerprint_hash, attempts, \
         created_at, expires_at, consumed_at, code_factor_id, code_hash, code_expires_at, \
         code_sent_at, code_sends, code_attempts"
    };
}

pub const INSERT_CHALLENGE: &str = concat!(
    "INSERT INTO mfa_challenges (id, user_id, secret_hash, created_ip, user_agent, \
     fingerprint_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6, now() + $7) RETURNING ",
    challenge_columns!(),
    ", now() AS db_now"
);

pub const FIND_CHALLENGE: &str = concat!(
    "SELECT ",
    challenge_columns!(),
    ", now() AS db_now FROM mfa_challenges WHERE id = $1"
);

pub const RECORD_CHALLENGE_ATTEMPT: &str = r#"
    UPDATE mfa_challenges
    SET attempts = attempts + 1
    WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() AND attempts < $2
    RETURNING attempts
"#;

/// `$2` factor, `$3` hash, `$4` ttl, `$5` resend_after, `$6` max_sends.
pub const SET_CHALLENGE_CODE: &str = r#"
    UPDATE mfa_challenges
    SET code_sends = CASE WHEN code_hash IS NOT NULL AND code_expires_at > now()
                          THEN code_sends + 1 ELSE 1 END,
        code_factor_id = $2, code_hash = $3, code_expires_at = now() + $4,
        code_sent_at = now(), code_attempts = 0
    WHERE id = $1
      AND consumed_at IS NULL AND expires_at > now()
      AND (code_sent_at IS NULL OR code_sent_at + $5 <= now())
      AND NOT (code_hash IS NOT NULL AND code_expires_at > now() AND code_sends >= $6)
    RETURNING code_expires_at
"#;

/// Why `SET_CHALLENGE_CODE` stored nothing.
pub const CHALLENGE_CODE_REFUSAL: &str = r#"
    SELECT (consumed_at IS NULL AND expires_at > now()) AS usable,
           (code_sent_at IS NOT NULL AND code_sent_at + $2 > now()) AS too_soon
    FROM mfa_challenges WHERE id = $1
"#;

pub const CONSUME_CHALLENGE: &str = r#"
    UPDATE mfa_challenges
    SET consumed_at = now()
    WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
"#;

// ── mfa_user_state ────────────────────────────────────────────────────────────

/// Always one row: the user's state (or nothing) and `now()`.
pub const LOCK_STATE: &str = r#"
    SELECT s.failures, s.locked_until, now() AS db_now
    FROM (SELECT 1) AS one
    LEFT JOIN mfa_user_state s ON s.user_id = $1
"#;

pub const ENSURE_USER_STATE: &str =
    "INSERT INTO mfa_user_state (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING";

/// One failure: `$2` window, `$3` threshold, `$4` lock duration.  `next`
/// below is the count including this failure (restarting once the window
/// passed); reaching the threshold locks and restarts the count.  Every
/// expression reads the row as locked by this `UPDATE`.
pub const RECORD_FAILURE: &str = r#"
    UPDATE mfa_user_state
    SET failures = CASE
            WHEN (CASE WHEN window_started_at + $2 <= now() THEN 0 ELSE failures END) + 1 >= $3
            THEN 0
            ELSE (CASE WHEN window_started_at + $2 <= now() THEN 0 ELSE failures END) + 1
        END,
        locked_until = CASE
            WHEN (CASE WHEN window_started_at + $2 <= now() THEN 0 ELSE failures END) + 1 >= $3
            THEN now() + $4
            ELSE locked_until
        END,
        window_started_at = CASE
            WHEN window_started_at + $2 <= now()
              OR (CASE WHEN window_started_at + $2 <= now() THEN 0 ELSE failures END) + 1 >= $3
            THEN now()
            ELSE window_started_at
        END
    WHERE user_id = $1
    RETURNING failures, locked_until, now() AS db_now
"#;

pub const CLEAR_FAILURES: &str = "DELETE FROM mfa_user_state WHERE user_id = $1";

// ── Housekeeping ──────────────────────────────────────────────────────────────

pub const DELETE_USER_CHALLENGES: &str = "DELETE FROM mfa_challenges WHERE user_id = $1";
pub const DELETE_USER_FACTORS: &str = "DELETE FROM mfa_factors WHERE user_id = $1";

/// Rows past `$1` retention.
pub const PURGE: &str = r#"
    WITH c AS (
        DELETE FROM mfa_challenges
        WHERE expires_at < now() - $1 OR consumed_at < now() - $1
        RETURNING 1
    ), f AS (
        DELETE FROM mfa_factors
        WHERE status = 'pending' AND expires_at < now() - $1
        RETURNING 1
    ), l AS (
        DELETE FROM mfa_user_state
        WHERE (locked_until IS NULL OR locked_until <= now())
          AND window_started_at < now() - $1
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM c) + (SELECT count(*) FROM f) + (SELECT count(*) FROM l)
"#;
