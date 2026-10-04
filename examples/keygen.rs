//! Generate the keys and secrets auth-lib needs.
//!
//! ```text
//! cargo run --example keygen
//! ```
//!
//! `AUTH_JWT_SIGNING_KEY` and `AUTH_REFRESH_SECRET` belong on the auth service
//! only.  `AUTH_JWT_VERIFYING_KEYS` goes to every service that verifies access
//! tokens.  During a key rotation, list the old and new verifying keys
//! separated by a comma.

use auth_lib::token::keys::{generate_refresh_secret, generate_signing_key};

fn main() -> Result<(), auth_lib::AuthError> {
    let keys = generate_signing_key()?;
    println!("# auth service only");
    println!("AUTH_JWT_SIGNING_KEY={}", keys.signing_key);
    println!("AUTH_REFRESH_SECRET={}", generate_refresh_secret()?);
    println!();
    println!("# every service that verifies access tokens");
    println!("AUTH_JWT_VERIFYING_KEYS={}", keys.verifying_key);
    Ok(())
}
