use rusqlite::{Connection, params, Result, Statement, Transaction};

pub struct X3DHDatabase {
    conn: Connection,
}

impl X3DHDatabase {

    /// Create the X3DH keys database if not exists
    pub fn new() -> Result<Self> {
        let conn = Connection::open("x3dh_keys.db")?;

        conn.execute(
            "create table if not exists keys (
             username TEXT NOT NULL PRIMARY KEY,
             ik BLOB NOT NULL,
             spk BLOB NOT NULL,
             signature_r BLOB NOT NULL,
             signature_s BLOB NOT NULL,
             verifying_key BLOB NOT NULL
         )",
            (),
        )?;

        conn.execute(
            "create table if not exists opk_bundle (
             opk BLOB NOT NULL,
             username TEXT NOT NULL,
             FOREIGN KEY(username) REFERENCES keys(username),
             PRIMARY KEY(opk, username)
         )",
            (),
        )?;

        Ok(X3DHDatabase { conn })
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
    pub fn user_exist(&self, username: &String) -> Result<bool> {
        let mut stmt: Statement = self.conn.prepare("SELECT 1 FROM keys WHERE username=:username")?;
        let exists: bool = stmt.exists(&[(":username", username.as_str())])?;

        Ok(exists)
    }

    /// Return the list of all the username
    ///
    /// # Output
    ///
    /// * Vec\<String\>: username list
    pub fn get_all_users(&self) -> Result<Vec<String>> {
        let mut stmt: Statement = self.conn.prepare("SELECT username FROM keys")?;

        let req_user_list: Result<Vec<String>> = stmt.query_map(params![], |row| {
            Ok(row.get(0)?)
        })?.collect();

        req_user_list
    }

    /// Insert X3DH keys
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `ik` (\[u8;32\]): Identity Key *(public key)*
    /// * `spk` (\[u8; 32\]): Signed Pre Key *(public key)*
    /// * `opk_bundle` (Vec\<\[u8; 32\]\>): Bundle of One Time Pre Key
    /// * `signature` (\[\[u8;32\]; 2\]): Signature *(\[r_bytes, s_bytes\])*
    /// * `verifying_key` (\[u8; 32\]): Verifying Key
    pub fn insert_x3dh_keys(&mut self, username: &String, ik: [u8; 32], spk: [u8; 32], opk_bundle: Vec<[u8; 32]>, signature: [[u8;32]; 2], verifying_key: [u8; 32]) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("INSERT INTO keys (username, ik, spk, signature_r, signature_s, verifying_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                   (username, ik, spk, signature[0], signature[1], verifying_key))?;

        tx.commit().expect("Should bd fine");

        self.add_opk_bundle(username, opk_bundle)
    }

    /// Update the Signed Pre Key, Signature and Verification Key of the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `spk` (\[u8;32\]): Signed Pre Key
    /// * `signature` (\[\[u8;32\];32\]): Signature
    /// * `verifying_key` (\[u8;32\]): Verifying Key
    pub fn update_spk(&mut self, username: &String, spk: [u8;32], signature: [[u8;32]; 2], verifying_key: [u8; 32]) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        match tx.execute("UPDATE keys SET spk = ?1, signature_r = ?2, signature_s = ?3, verifying_key = ?4 WHERE username = ?5",
                         params![spk, signature[0], signature[1], verifying_key, username]) {
            Ok(updated) => println!("{} row updated", updated),
            Err(err) => println!("update failed: {}", err),
        }

        tx.commit()
    }

    /// Return the public keys *(X3DH)* of the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    ///
    /// # Output
    ///
    /// (ik_public_key, spk_public_key, opk_public_key, signature, verifying_key: (\[u8; 32\], \[u8; 32\], Option\<\[u8;32\]\>, \[\[u8; 32\]; 2\], \[u8; 32\])
    pub fn get_public_keys(&mut self, username: String) -> Result<([u8; 32], [u8; 32], Option<[u8;32]>, [[u8; 32]; 2], [u8; 32])> {
        let mut stmt: Statement = self.conn.prepare("SELECT ik, spk, signature_r, signature_s, verifying_key FROM keys WHERE username = ?")?;

        let opk_key: Option<[u8; 32]> = self.get_opk_key(&username).unwrap();//self.opk_bundle_database.get_opk_key(&username, tx).unwrap(); // TODO should be better handle

        let mut result = stmt.query_map(&[username.as_str()], |row| {
            let ik: [u8; 32] = row.get(0)?;
            let spk: [u8; 32] = row.get(1)?;
            let signature_r: [u8; 32] = row.get(2)?;
            let signature_s: [u8; 32] = row.get(3)?;
            let verifying_key: [u8; 32] = row.get(4)?;

            Ok((ik, spk, opk_key, [signature_r, signature_s], verifying_key))
        })?;

        if let Some(result) = result.next() {
            result
        } else {
            Err(rusqlite::Error::QueryReturnedNoRows)
        }
    }

    /// Add One Time Pre Key bundle for the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `opk_bundle` (Vec\<\[u8; 32\]\>): Bundle of One Time Pre Key
    pub fn add_opk_bundle(&mut self, username: &String, opk_bundle: Vec<[u8;32]>) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        for opk in opk_bundle {
            tx.execute("INSERT INTO opk_bundle (opk, username) VALUES (?1, ?2)",
                       (opk, username))?;
        }

        tx.commit()
    }

    /// Get the One Time Pre Key bundle of the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    ///
    /// # Output
    ///
    /// opk_bundle (Vec\<\[u8;32\]\>)
    fn get_opk_bundle(&self, username: &String) -> Result<Vec<[u8; 32]>> {
        let mut stmt: Statement = self.conn.prepare("SELECT opk FROM opk_bundle WHERE username=:username")?;

        let req_user_opk_bundle: Result<Vec<[u8; 32]>> = stmt.query_map(params![username], |row| {
            Ok(row.get(0)?)
        })?.collect();

        req_user_opk_bundle
    }

    /// Get and remove a single One Time Pre Key of the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    ///
    /// # Ouptut
    ///
    /// opk_key (\[u8; 32\])
    fn get_opk_key(&self, username: &String) -> Result<Option<[u8; 32]>> {
        let user_opk_bundle: Vec<[u8; 32]> = self.get_opk_bundle(username).unwrap();
        if user_opk_bundle.is_empty() { return Ok(None) };

        Ok(Some(user_opk_bundle[0]))
    }

    pub fn delete_opk_key(&mut self, opk: [u8; 32]) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("DELETE FROM opk_bundle WHERE opk=?1",
                   params![opk])?;

        tx.commit()
    }
}