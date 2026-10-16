//! Generate the keys z-auth-mfa needs.
//!
//! ```text
//! cargo run -p z-auth-mfa --example mfa_keygen
//! ```
//!
//! Both belong on the service that runs z-auth-mfa (the authority in
//! federation mode) and must stay the same across its instances.  Losing
//! `AUTH_MFA_ENCRYPTION_KEY` makes every TOTP factor unusable; losing
//! `AUTH_MFA_HASH_KEY` invalidates every recovery code.  To rotate the
//! encryption key, move the old one to `AUTH_MFA_PREVIOUS_ENCRYPTION_KEYS`.

fn main() -> Result<(), z_auth::AuthError> {
    let keys = z_auth_mfa::keys::generate_keys()?;
    println!("AUTH_MFA_ENCRYPTION_KEY={}", keys.encryption_key);
    println!("AUTH_MFA_HASH_KEY={}", keys.hash_key);
    Ok(())
}
