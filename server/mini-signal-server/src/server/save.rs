use rusqlite::{Connection, Result};
use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Error
}, Argon2};

fn main() {
    println!("Hello, world!");
    create_database();
    test_passwords();
}

fn test_passwords() -> Result<(), Error> {
    let password = b"hunter42"; // Bad password; don't actually use!
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password, &salt)?.to_string();
    println!("{:?}", password_hash);
    // Verify password against PHC string.
    //
    // NOTE: hash params from `parsed_hash` are used instead of what is configured in the
    // `Argon2` instance.
    let parsed_hash = PasswordHash::new(&password_hash)?;
    println!("{:?}", parsed_hash);
    assert!(Argon2::default().verify_password(password, &parsed_hash).is_ok());

    Ok(())
}

fn create_database() -> Result<()> {
    let conn = Connection::open("passwords.db")?;

    conn.execute(
        "create table if not exists passwords (
             id integer primary key,
             username text not null,
             password text not null
         )",
        (),
    )?;

    Ok(())
}