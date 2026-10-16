//! SQL query constants for `identity_external_identities` and
//! `security_flow_states`.

macro_rules! identity_columns {
    () => {
        "id, user_id, provider, issuer, subject, email, created_at, last_login_at"
    };
}

pub const FIND_BY_SUBJECT: &str = concat!(
    "SELECT ",
    identity_columns!(),
    " FROM identity_external_identities WHERE issuer = $1 AND subject = $2"
);

pub const FIND: &str = concat!(
    "SELECT ",
    identity_columns!(),
    " FROM identity_external_identities WHERE id = $1"
);

pub const LIST_FOR_USER: &str = concat!(
    "SELECT ",
    identity_columns!(),
    " FROM identity_external_identities WHERE user_id = $1 ORDER BY created_at, id"
);

pub const INSERT: &str = concat!(
    "INSERT INTO identity_external_identities (user_id, provider, issuer, subject, email) \
     VALUES ($1, $2, $3, $4, $5) RETURNING ",
    identity_columns!()
);

pub const DELETE: &str = "DELETE FROM identity_external_identities WHERE id = $1";

pub const RECORD_LOGIN: &str =
    "UPDATE identity_external_identities SET last_login_at = now() WHERE id = $1";

// ── Flow states ───────────────────────────────────────────────────────────────

pub const FLOW_PUT: &str = r#"
    INSERT INTO security_flow_states (key, value, expires_at)
    VALUES ($1, $2, now() + $3)
    ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
"#;

/// Deletes the row whatever its age; only a live one is returned.
pub const FLOW_TAKE: &str = r#"
    DELETE FROM security_flow_states
    WHERE key = $1
    RETURNING value, expires_at > now() AS live
"#;

pub const FLOW_PURGE: &str = "DELETE FROM security_flow_states WHERE expires_at <= now()";
