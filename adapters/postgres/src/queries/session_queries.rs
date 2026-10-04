//! SQL query constants for the `sessions` and `session_generations` tables.
//!
//! All queries use `$N` positional parameters — values are never interpolated.
//! Every timestamp comes from `now()`; the caller only binds durations
//! (`std::time::Duration` → `interval`).  `now()` is fixed for the whole
//! transaction, so a session's `created_at` equals its first generation's
//! `issued_at`, and a rotation's `superseded_at` equals the next `issued_at`.

pub const INSERT_SESSION: &str = r#"
    INSERT INTO sessions (
        user_id, secret, created_ip, user_agent, idle_expires_at, absolute_expires_at
    )
    VALUES ($1, $2, $3, $4, now() + $5, now() + $6)
    RETURNING
        id, user_id, secret, status, end_reason, created_ip, user_agent,
        current_generation, created_at, idle_expires_at, absolute_expires_at, ended_at
"#;

pub const FIND_SESSION: &str = r#"
    SELECT
        id, user_id, secret, status, end_reason, created_ip, user_agent,
        current_generation, created_at, idle_expires_at, absolute_expires_at, ended_at
    FROM sessions
    WHERE id = $1
"#;

/// Session + presented generation (`$2`) + current generation + `now()`,
/// in one round trip.
pub const LOAD_FOR_REFRESH: &str = r#"
    SELECT
        s.id, s.user_id, s.secret, s.status, s.end_reason, s.created_ip, s.user_agent,
        s.current_generation, s.created_at, s.idle_expires_at, s.absolute_expires_at,
        s.ended_at,
        now()               AS db_now,
        p.id                AS p_id,
        p.generation        AS p_generation,
        p.issued_ip         AS p_issued_ip,
        p.issued_at         AS p_issued_at,
        p.access_expires_at AS p_access_expires_at,
        p.superseded_at     AS p_superseded_at,
        c.id                AS c_id,
        c.generation        AS c_generation,
        c.issued_ip         AS c_issued_ip,
        c.issued_at         AS c_issued_at,
        c.access_expires_at AS c_access_expires_at,
        c.superseded_at     AS c_superseded_at
    FROM sessions s
    LEFT JOIN session_generations p
           ON p.session_id = s.id AND p.generation = $2
    LEFT JOIN session_generations c
           ON c.session_id = s.id AND c.generation = s.current_generation
    WHERE s.id = $1
"#;

/// Active, unexpired sessions of a user, oldest first.
/// Uses the partial index `idx_sessions_user_active`.
pub const LIST_ACTIVE_FOR_USER: &str = r#"
    SELECT
        id, user_id, secret, status, end_reason, created_ip, user_agent,
        current_generation, created_at, idle_expires_at, absolute_expires_at, ended_at
    FROM sessions
    WHERE user_id = $1
      AND status = 'active'
      AND idle_expires_at > now()
      AND absolute_expires_at > now()
    ORDER BY created_at ASC
"#;

/// Compare-and-swap: advance only if still at the expected generation and
/// active.  No row returned means a concurrent rotation won (or the
/// session ended).  Concurrent callers serialise on the row lock and the
/// loser re-evaluates the `WHERE` clause after the winner commits.
pub const ADVANCE_SESSION: &str = r#"
    UPDATE sessions
    SET current_generation = current_generation + 1,
        idle_expires_at    = now() + $3
    WHERE id = $1
      AND current_generation = $2
      AND status = 'active'
    RETURNING
        id, user_id, secret, status, end_reason, created_ip, user_agent,
        current_generation, created_at, idle_expires_at, absolute_expires_at, ended_at
"#;

pub const END_SESSION: &str = r#"
    UPDATE sessions
    SET status = $2, end_reason = $3, ended_at = now()
    WHERE id = $1 AND status = 'active'
"#;

/// From `active` or `revoked`; keeps an existing `ended_at`.
pub const MARK_COMPROMISED: &str = r#"
    UPDATE sessions
    SET status = 'compromised', end_reason = $2, ended_at = COALESCE(ended_at, now())
    WHERE id = $1
"#;

pub const END_ALL_FOR_USER: &str = r#"
    UPDATE sessions
    SET status = $2, end_reason = $3, ended_at = now()
    WHERE user_id = $1 AND status = 'active'
    RETURNING id
"#;

/// Sessions purgeable for longer than `$1`.  The `LEAST(...)` expression must
/// match `idx_sessions_purge` verbatim.  Generations cascade.
pub const PURGE_SESSIONS: &str = r#"
    DELETE FROM sessions
    WHERE LEAST(idle_expires_at, absolute_expires_at, COALESCE(ended_at, 'infinity'))
          < now() - $1
"#;

pub const INSERT_GENERATION: &str = r#"
    INSERT INTO session_generations (session_id, generation, issued_ip, access_expires_at)
    VALUES ($1, $2, $3, now() + $4)
    RETURNING id, session_id, generation, issued_ip, issued_at, access_expires_at, superseded_at
"#;

pub const FIND_GENERATION: &str = r#"
    SELECT id, session_id, generation, issued_ip, issued_at, access_expires_at, superseded_at
    FROM session_generations
    WHERE session_id = $1 AND generation = $2
"#;

pub const SUPERSEDE_GENERATION: &str = r#"
    UPDATE session_generations
    SET superseded_at = now()
    WHERE session_id = $1 AND generation = $2
"#;

/// Keep only the newest `history_size` generations: `$2 = newest - history_size`.
pub const TRIM_GENERATIONS: &str = r#"
    DELETE FROM session_generations
    WHERE session_id = $1 AND generation <= $2
"#;
