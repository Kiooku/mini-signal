use argon2::{password_hash::{
    PasswordHasher, SaltString
}, Argon2};

pub fn get_hash(password: &String) -> String {
    let salt: SaltString = match SaltString::from_b64("vRpg/cByxpn6m1L0ZPF5ew") { //SaltString::generate(&mut OsRng);
        Ok(salt) => salt,
        Err(error) => panic!("{}", error),
    };

    let argon2: Argon2 = Argon2::default();
    let hash: String = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(error) => panic!("{}", error),
    };
    hash
}