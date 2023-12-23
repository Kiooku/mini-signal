use rusqlite::{Connection, Result, params, Transaction, Statement};

pub struct MessageDatabase {
    conn: Connection
}

impl MessageDatabase {
    pub fn new() -> Result<Self> {
        let conn: Connection = Connection::open("messages.db")?;

        conn.execute("CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_receiver TEXT NOT NULL,
            username_sender TEXT NOT NULL,
            header_encrypted BLOB NOT NULL,
            header_nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            ciphertext_nonce BLOB NOT NULL,
            ek_sender BLOB,
            opk_used BLOB
        )", ())?;

        Ok(MessageDatabase { conn })
    }

    pub fn get_all_user_messages(&self, username_receiver: &String) -> Result<Vec<(i64, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<[u8;32]>, Option<[u8;32]>)>> {
        let mut stmt: Statement = self.conn.prepare("SELECT message_id, username_sender, header_encrypted, header_nonce, ciphertext, ciphertext_nonce, ek_sender, opk_used FROM messages WHERE username_receiver=?")?;

        let mut result = stmt.query_map(&[username_receiver], |row| {
            let message_id: i64 = row.get(0)?;
            let username_sender: String = row.get(1)?;
            let header_encrypted: Vec<u8> = row.get(2)?;
            let header_nonce: Vec<u8> = row.get(3)?;
            let ciphertext: Vec<u8> = row.get(4)?;
            let nonce: Vec<u8> = row.get(5)?;
            //let ek_sender: Option<[u8;32]> = if row.get::<usize, [u8;32]>(6).is_ok() { Some(row.get::<usize, [u8;32]>(6).unwrap()) } else { None };
            let ek_sender: Option<[u8;32]> = if row.get(6).is_ok() { Some(row.get(6).unwrap()) } else { None };
            let opk_used: Option<[u8;32]> = if row.get(7).is_ok() { Some(row.get(7).unwrap()) } else { None };

            Ok((message_id, username_sender, header_encrypted, header_nonce, ciphertext, nonce, ek_sender, opk_used))
        })?;

        let mut messages: Vec<(i64, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<[u8;32]>, Option<[u8;32]>)> = Vec::new();

        while let Some(result) = result.next() {
            messages.push(result.unwrap());
        };

        Ok(messages)
    }

    pub fn add_message(&mut self, username_receiver: &String, username_sender: &String,
                       header_encrypted: Vec<u8>, header_nonce: Vec<u8>,
                       ciphertext: Vec<u8>, nonce: Vec<u8>,
                       ek_sender: Option<[u8;32]>, opk_used: Option<[u8;32]>) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("INSERT INTO messages
        (username_receiver, username_sender, header_encrypted, header_nonce, ciphertext, ciphertext_nonce, ek_sender, opk_used)\
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                   (username_receiver, username_sender, header_encrypted, header_nonce, ciphertext, nonce, ek_sender, opk_used))?;

        tx.commit()
    }

    pub fn delete_message(&mut self, message_id: i64) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("DELETE FROM messages WHERE message_id=?1",
                   params![message_id])?;

        tx.commit()
    }
}