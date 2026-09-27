//! Numeric conversions between auth-lib types and Postgres columns.
//! (Enum ↔ ENUM mapping lives in [`crate::enums`].)

use auth_lib::AuthError;

/// `u32` generation ↔ Postgres `integer`.
pub(crate) fn to_db_generation(generation: u32) -> Result<i32, AuthError> {
    i32::try_from(generation).map_err(|_| AuthError::Storage("generation overflow".into()))
}

pub(crate) fn from_db_generation(generation: i32) -> Result<u32, AuthError> {
    u32::try_from(generation).map_err(|_| AuthError::Storage("negative generation".into()))
}
