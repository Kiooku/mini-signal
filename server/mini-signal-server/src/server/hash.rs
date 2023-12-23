use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Error
}, Argon2};

pub fn check_hash(password_hash: String) -> bool {
    let parsed_hash = PasswordHash::new(&password_hash)?;
    Argon2::default().verify_password(password_hash.as_ref(), &parsed_hash).is_ok()
}