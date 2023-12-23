use rusqlite::{Connection, params, Result, Statement, Transaction};
use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Error
}, Argon2};
// Do I need tokio_rusqlite

pub struct PasswordDatabase {
    conn: Connection
}

impl PasswordDatabase {

    /// Create the Password database if not exists
    pub fn new() -> Result<Self> {
        let conn: Connection = Connection::open("passwords.db")?;

        conn.execute("CREATE TABLE IF NOT EXISTS passwords (
             username TEXT PRIMARY KEY NOT NULL,
             password TEXT NOT NULL
         )", ())?;

        Ok(PasswordDatabase { conn })
    }

    /// Check if the username exist
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    ///
    /// # Output
    ///
    /// * bool
    pub fn user_exist(&self, username: String) -> Result<bool> {
        let mut stmt: Statement = self.conn.prepare("SELECT 1 FROM passwords WHERE username=:username")?;
        let exists: bool = stmt.exists(&[(":username", username.as_str())])?;

        Ok(exists)
    }

    /// Insert password for the corresponding username
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `password` (String): Password *(Argon2id)*
    pub fn insert_user(&mut self, username: &String, password: &String) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        let password_hash = PasswordDatabase::get_hash(password);
        tx.execute("INSERT INTO passwords (username, password) VALUES (?1, ?2)",
                   (username, password_hash))?;

        tx.commit()
    }

    /// Check if the hash input correspond to the one store
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `password` (String): Password
    pub fn check_password(&self, username: &String, password: String) -> Result<bool> {
        let mut stmt: Statement = self.conn.prepare("SELECT password FROM passwords WHERE username=:username;")?;

        let req_user_password: Result<Vec<String>> = stmt.query_map(params![username], |row| {
            Ok(row.get(0)?)
        })?.collect();

        let user_password_hash: Vec<String> = req_user_password?;
        if user_password_hash.is_empty() { return Ok(false) };
        let parsed_hash: PasswordHash = match PasswordHash::new(&user_password_hash[0]) {
            Ok(parsed_hash) => parsed_hash,
            Err(error) => panic!("{}", error),
        };

        Ok(Argon2::default().verify_password(password.as_ref(), &parsed_hash).is_ok())
    }

    fn get_hash(password: &String) -> String {
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
}