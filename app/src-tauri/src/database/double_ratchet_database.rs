use rusqlite::{Connection, Result, params, Transaction, Statement};
use crate::database::message_database::MessageDatabase;

pub struct DoubleRatchetDatabase {
    conn: Connection
}
// https://docs.rs/crate/rusqlcipher/latest
impl DoubleRatchetDatabase {
    pub fn new() -> Result<Self> {
        let conn: Connection = Connection::open("double_ratchet.db")?;

        // TODO store the data necessary to continue the double ratchet
        /*
        pub dh_s: Option<(ReusableSecret, PublicKey25519)>, // DH Ratchet key pair (the "sending" or "self" ratchet key)
        pub dh_r: Option<PublicKey25519>, // DH Ratchet public key (the "received" or "remote" key)
        pub rk: Option<[u8; 32]>, // 32-byte Root Key
        pub ck_s: Option<[u8; 32]>, // 32-byte Chain Keys for sending
        pub ck_r: Option<[u8; 32]>, // 32-byte Chain Keys for receiving
        pub hk_s: Option<[u8; 32]>, // 32-byte Header Keys for sending
        pub hk_r: Option<[u8; 32]>, // 32-byte Header Keys for receiving
        pub nhk_s: Option<[u8; 32]>, // 32-byte Next Header Keys for sending
        pub nhk_r: Option<[u8; 32]>, // 32-byte Next Header Keys for receiving
        pub n_s: u8, // Message numbers for sending
        pub n_r: u8, // Message numbers for receiving
        pub pn: u8, // Number of messages in previous sending chain
        pub mkskipped: HashMap<([u8; 32], u8), [u8; 32]>, // Dictionary of skipped-over message keys, indexed by header key and message number.
         */
        conn.execute("CREATE TABLE IF NOT EXISTS double_ratchet (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_receiver TEXT NOT NULL,
            message TEXT NOT NULL
        )", ())?;

        Ok(DoubleRatchetDatabase { conn })
    }
}