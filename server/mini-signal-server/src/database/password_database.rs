use rusqlite::{Connection, params, Result, Statement, Transaction};

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

        let password_hash = password;//PasswordDatabase::get_hash(password);
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

        Ok(password == user_password_hash[0])
    }
}