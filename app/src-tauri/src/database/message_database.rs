use rusqlite::{Connection, Result, params, Transaction, Statement};

pub struct MessageDatabase {
    conn: Connection
}
// https://docs.rs/crate/rusqlcipher/latest
impl MessageDatabase {
    pub fn new() -> Result<Self> {
        let conn: Connection = Connection::open("messages.db")?;

        conn.execute("CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_sender TEXT NOT NULL,
            message TEXT NOT NULL
        )", ())?;

        Ok(MessageDatabase { conn })
    }

    // TODO implement the function necessary to work with the database
}