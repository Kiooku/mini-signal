use rusqlite::{Connection, Result, params, Transaction, Statement};

pub struct MessageDatabase {
    conn: Connection
}

impl MessageDatabase {
    pub fn new(username: &str) -> Result<Self> {
        let conn: Connection = Connection::open(format!("messages_{}.db", username.to_lowercase()))?;

        conn.execute("CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_sender TEXT NOT NULL,
            username_receiver TEXT NOT NULL,
            message TEXT NOT NULL
        )", ())?;

        Ok(MessageDatabase { conn })
    }

    pub fn get_messages_with(&self, username_receiver: &str) -> Result<Vec<(String, String, String)>> {
        let mut stmt: Statement = self.conn.prepare("SELECT message_id, username_sender, username_receiver, message FROM messages WHERE username_sender = ?1 OR username_receiver = ?1 ORDER BY message_id ASC")?;

        let mut result = stmt.query_map(&[username_receiver], |row| {
            let username_sender: String = row.get(1)?;
            let username_receiver: String = row.get(2)?;
            let message: String = row.get(3)?;

            Ok((username_sender, username_receiver, message))
        })?;

        let mut messages: Vec<(String, String, String)> = Vec::new();

        while let Some(result) = result.next() {
            messages.push(result.unwrap());
        };

        Ok(messages)
    }

    pub fn insert_message(&mut self, username_sender: &str, username_receiver: &str, message: &str) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("INSERT INTO messages (username_sender, username_receiver, message) VALUES (?1, ?2, ?3)",
                   (username_sender, username_receiver, message))?;

        tx.commit()
    }
}