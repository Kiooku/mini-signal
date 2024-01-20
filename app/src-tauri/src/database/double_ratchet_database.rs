use std::collections::HashMap;
use argon2::password_hash::Ident;
use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::ed25519::SignatureBytes;
use rusqlite::{Connection, Result, params, Transaction, Statement};
use crate::double_ratchet::state::State;
use serde::{Serialize, Deserialize};
use serde::de::value::MapDeserializer;
use x25519_dalek::{PublicKey, StaticSecret};
use crate::communication::client::Client;
use crate::double_ratchet::double_ratchet::DoubleRatchetHE;
use crate::communication::key_collection::ClientKeyCollection;
use serde_json::Value;
use crate::x3dh::x3dh::{IdentityKey, OneTimePrekey, SignedPrekey};

#[derive(Serialize, Deserialize)]
struct MkSkippedForSQL {
    mk_skipped: HashMap<([u8; 32], u8), [u8; 32]>,
}

pub struct DoubleRatchetDatabase {
    conn: Connection
}
// https://docs.rs/crate/rusqlcipher/latest
impl DoubleRatchetDatabase {
    pub fn new(username: &str) -> Result<Self> {
        // Create one database per user on the same computer to limit the leak of information (the database should be encrypted with the user password)
        let conn: Connection = Connection::open(format!("double_ratchet_{}.db", username.to_lowercase()))?;

        // Store the X3DH keys but also the information necessary to continue a Double ratchet communication
        conn.execute(
            "create table if not exists x3dh (
             username TEXT NOT NULL PRIMARY KEY,
             ik_pub BLOB NOT NULL,
             ik_priv BLOB NOT NULL,
             spk_pub BLOB NOT NULL,
             spk_priv BLOB NOT NULL,
             signature_r BLOB NOT NULL,
             signature_s BLOB NOT NULL,
             verifying_key BLOB NOT NULL
         )",
            (),
        )?;

        conn.execute(
            "create table if not exists opk_bundle (
             opk_pub BLOB NOT NULL,
             opk_priv BLOB NOT NULL,
             username TEXT NOT NULL,
             FOREIGN KEY(username) REFERENCES x3dh(username),
             PRIMARY KEY(opk_pub, username)
         )",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS double_ratchet (
            username_interlocutor TEXT NOT NULL PRIMARY KEY,
            ad BLOB NOT NULL,
            dh_s_priv BLOB NOT NULL,
            dh_s_pub BLOB NOT NULL,
            dh_r BLOB,
            rk BLOB NOT NULL,
            ck_s BLOB,
            ck_r BLOB,
            hk_s BLOB,
            hk_r BLOB,
            nhk_s BLOB NOT NULL,
            nhk_r BLOB NOT NULL,
            n_s INTEGER NOT NULL,
            n_r INTEGER NOT NULL,
            pn INTEGER NOT NULL,
            mkskipped TEXT NOT NULL
        )", ())?;

        Ok(DoubleRatchetDatabase { conn })
    }

    /// # X3DH database

    /// Insert X3DH keys
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `ik` (IdentityKey): Identity Key
    /// * `spk` (SignedPrekey): Signed Pre Key
    /// * `opk_bundle` (Vec\<OneTimePrekey\>): Bundle of One Time Pre Key
    /// * `signature` (Signature]): Signature
    /// * `verifying_key` (VerifyingKey): Verifying Key
    fn insert_x3dh_keys(&mut self, username: &String, ik: IdentityKey, spk: SignedPrekey, opk_bundle: &Vec<OneTimePrekey>, signature: Signature, verifying_key: VerifyingKey) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("INSERT INTO x3dh (username, ik_pub, ik_priv, spk_pub, spk_priv, signature_r, signature_s, verifying_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                   (username, ik.get_public_key().to_bytes(), ik.get_private_key().to_bytes(), spk.get_public_key().to_bytes(), spk.get_private_key().to_bytes(), signature.r_bytes().to_vec(), signature.s_bytes().to_vec(), verifying_key.to_bytes()))?;

        tx.commit().expect("Should bd fine");

        self.add_opk_bundle(username, opk_bundle)
    }

    /// Update the Signed Pre Key, Signature and Verification Key of the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    /// * `spk` (SignedPrekey): Signed Pre Key
    /// * `signature` (Signature): Signature
    /// * `verifying_key` (VerifyingKey): Verifying Key
    pub fn update_spk(&mut self, username: &String, spk: SignedPrekey, signature: Signature, verifying_key: VerifyingKey) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        match tx.execute("UPDATE x3dh SET spk_pub = ?1, spk_priv = ?2, signature_r = ?3, signature_s = ?4, verifying_key = ?5 WHERE username = ?6",
                         params![spk.get_public_key().to_bytes(), spk.get_private_key().to_bytes(), signature.r_bytes().to_vec(), signature.s_bytes().to_vec(), verifying_key.to_bytes(), username]) {
            Ok(updated) => println!("{} row updated", updated),
            Err(err) => println!("update failed: {}", err),
        }

        tx.commit()
    }

    /// Return the *X3DH* keys of the corresponding `username`
    ///
    /// # Arguments
    ///
    /// * `username` (String): Username
    ///
    /// # Output
    ///
    /// (`IdentityKey`, `SignedPrekey`, `Signature`, `VerifyingKey`)
    pub fn get_x3dh_keys(&mut self, username: String) -> Result<(IdentityKey, SignedPrekey, Vec<OneTimePrekey>, Signature, VerifyingKey)> {
        let mut stmt: Statement = self.conn.prepare("SELECT ik_pub, ik_priv, spk_pub, spk_priv, signature_r, signature_s, verifying_key FROM x3dh WHERE username = ?")?;

        let opk_bundle: Vec<OneTimePrekey> = self.get_opk_bundle(&username).unwrap();

        let mut result = stmt.query_map(&[username.as_str()], |row| {
            let ik_pub: [u8; 32] = row.get(0)?;
            let ik_priv: [u8; 32] = row.get(1)?;
            let spk_pub: [u8; 32] = row.get(2)?;
            let spk_priv: [u8; 32] = row.get(3)?;
            let signature_r: [u8; 32] = row.get(4)?;
            let signature_s: [u8; 32] = row.get(5)?;
            let verifying_key: [u8; 32] = row.get(6)?;

            let ik: IdentityKey = IdentityKey::from(PublicKey::from(ik_pub), StaticSecret::from(ik_priv));
            let spk: SignedPrekey = SignedPrekey::from(PublicKey::from(spk_pub), StaticSecret::from(spk_priv));
            let mut merged_signature: [u8; 64] = [0; 64]; // Initialize with zeros or any default value
            merged_signature[0..32].copy_from_slice(&signature_r);
            merged_signature[32..].copy_from_slice(&signature_s);
            let signature: Signature = Signature::from(SignatureBytes::from(merged_signature));

            Ok((ik, spk, opk_bundle.clone(), signature, VerifyingKey::from_bytes(&verifying_key).unwrap()))
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
    /// * `opk_bundle` (Vec\<OneTimePrekey>): Bundle of One Time Pre Key
    pub fn add_opk_bundle(&mut self, username: &String, opk_bundle: &Vec<OneTimePrekey>) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        for opk in opk_bundle {
            tx.execute("INSERT INTO opk_bundle (opk_pub, opk_priv, username) VALUES (?1, ?2, ?3)",
                       (opk.get_public_key().to_bytes(), opk.get_private_key().to_bytes(), username))?;
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
    /// opk_bundle (Vec\<OneTimePrekey>)
    fn get_opk_bundle(&self, username: &String) -> Result<Vec<OneTimePrekey>> {
        let mut stmt: Statement = self.conn.prepare("SELECT opk_pub, opk_priv FROM opk_bundle WHERE username=:username")?;

        let req_user_opk_bundle: Result<Vec<OneTimePrekey>> = stmt.query_map(params![username], |row| {
            let opk_pub: [u8;32] = row.get(0)?;
            let opk_priv: [u8;32] = row.get(1)?;
            Ok(OneTimePrekey::from(PublicKey::from(opk_pub), StaticSecret::from(opk_priv)))
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
    pub fn get_opk_key(&self, opk_pub: [u8; 32]) -> Result<OneTimePrekey> {
        let mut stmt: Statement = self.conn.prepare("SELECT opk_pub, opk_priv FROM opk_bundle WHERE opk_pub=?1")?;

        let mut req = stmt.query_map(params![opk_pub], |row| {
            let opk_pub: [u8;32] = row.get(0)?;
            let opk_priv: [u8;32] = row.get(1)?;
            Ok(OneTimePrekey::from(PublicKey::from(opk_pub), StaticSecret::from(opk_priv)))
        })?;

        if let Some(result) = req.next() {
            result
        } else {
            Err(rusqlite::Error::QueryReturnedNoRows)
        }
    }

    pub fn delete_opk_key(&mut self, opk: OneTimePrekey) -> Result<()> {
        let tx: Transaction = self.conn.transaction()?;

        tx.execute("DELETE FROM opk_bundle WHERE opk_pub=?1 AND opk_priv=?2",
                   params![opk.get_public_key().to_bytes(), opk.get_private_key().to_bytes()])?;

        tx.commit()
    }

    /// # Double Ratchet database

    /// Store the communication HashMap from the Client object (communication::client::Client)
    fn insert_double_ratchet_information(&mut self, username_interlocutor: String, ad: Vec<u8>, state: State) -> Result<()> {
        let mkskipped_for_sql: MkSkippedForSQL = MkSkippedForSQL { mk_skipped: state.mkskipped };
        let tx: Transaction = self.conn.transaction()?;

        // REPLACE in SQLite = INSERT OR REPLACE
        tx.execute("REPLACE INTO double_ratchet VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (username_interlocutor, ad,
                    state.dh_s.clone().unwrap().0.to_bytes(), state.dh_s.clone().unwrap().1.to_bytes(), state.dh_r.as_ref().map_or(vec![], |key| key.as_bytes().to_vec()),
                    state.rk.unwrap_or([0; 32]), state.ck_s.unwrap_or([0; 32]), state.ck_r.unwrap_or([0; 32]),
                    state.hk_s.unwrap_or([0; 32]), state.hk_r.unwrap_or([0; 32]), state.nhk_s.unwrap_or([0; 32]), state.nhk_r.unwrap_or([0; 32]),
                    state.n_s, state.n_r, state.pn,
                    serde_json::to_string(&mkskipped_for_sql).unwrap()
                   ))?;

        tx.commit()
    }

    /// Load the communication HashMap from the Client object (communication::client::Client)
    fn load_double_ratchet_information(&self) -> Result<HashMap<String, (Vec<u8>, DoubleRatchetHE)>> {
        let mut communication: HashMap<String, (Vec<u8>, DoubleRatchetHE)> = HashMap::new();
        let mut stmt: Statement = self.conn.prepare("SELECT username_interlocutor, ad, dh_s_priv, dh_s_pub, dh_r, rk, ck_s, ck_r, hk_s, hk_r, nhk_s, nhk_r, n_s, n_r, pn, mkskipped FROM double_ratchet")?;

        // TODO check if it works, otherwise use the message_database query to iterate over the rows
        let _ = stmt.query_map(params![], |row| {
            let username_interlocutor: String = row.get(0)?;
            let ad: Vec<u8> = row.get(1)?;
            let dh_s_priv: [u8; 32] = row.get(2)?;
            let dh_s_pub: [u8; 32] = row.get(3)?;
            let dh_r: [u8; 32] = row.get(4)?;
            let rk: [u8; 32] = row.get(5)?;
            let ck_s: [u8; 32] = row.get(6)?;
            let ck_r: [u8; 32] = row.get(7)?;
            let hk_s: [u8; 32] = row.get(8)?;
            let hk_r: [u8; 32] = row.get(9)?;
            let nhk_s: [u8; 32] = row.get(10)?;
            let nhk_r: [u8; 32] = row.get(11)?;
            let n_s: u8 = row.get(12)?;
            let n_r: u8 = row.get(13)?;
            let pn: u8 = row.get(14)?;
            let mkskipped: String = row.get(15)?;

            // Deserialize mkskipped to get the HashMap<([u8; 32], u8), [u8; 32]>)
            let mut data: HashMap<String, Value> = serde_json::from_str(&mkskipped).unwrap();
            let deserialize_mkskipped: MkSkippedForSQL = MkSkippedForSQL::deserialize(MapDeserializer::new(data.into_iter())).unwrap();

            let current_interlocutor_state: State = State::from(
                Some((StaticSecret::from(dh_s_priv), PublicKey::from(dh_s_pub))),
                if dh_r == [0; 32] { None } else { Some(PublicKey::from(dh_r)) },
                Some(rk),
                if ck_s == [0; 32] { None } else { Some(ck_s) },
                if ck_r == [0; 32] { None } else { Some(ck_r) },
                if hk_s == [0; 32] { None } else { Some(hk_s) },
                if hk_r == [0; 32] { None } else { Some(hk_r) },
                Some(nhk_s),
                Some(nhk_r),
                n_s,
                n_r,
                pn,
                deserialize_mkskipped.mk_skipped
            );
            let current_interlocutor_double_ratchet: DoubleRatchetHE = DoubleRatchetHE::from(current_interlocutor_state);

            communication.insert(username_interlocutor, (ad, current_interlocutor_double_ratchet));
            Ok(())
        })?;

       Ok(communication)
    }

    pub fn insert_client(&mut self, client: Client) -> Result<()> {
        let client_keys = client.get_keys();
        self.insert_x3dh_keys(&client.get_client_name(),
                              client_keys.get_ik(),
                              client_keys.get_spk(),
                              client_keys.get_opk_bundle(),
                              client_keys.get_signature(),
                              client_keys.get_verifying_key())
    }

    pub fn update_client(&mut self, client: &Client) -> Result<()> {
        for (interlocutor, (ad, interlocutor_double_ratchet)) in client.get_communication() {
            self.insert_double_ratchet_information(interlocutor.clone(), ad, interlocutor_double_ratchet.state).expect(&format!("Error when inserting {} double ratchet information", interlocutor));
        }
        Ok(())
    }

    pub fn load_client(&mut self, username: &str) -> Result<Client> {
        let communication: HashMap<String, (Vec<u8>, DoubleRatchetHE)> = self.load_double_ratchet_information().unwrap();
        let x3dh_keys: (IdentityKey, SignedPrekey, Vec<OneTimePrekey>, Signature, VerifyingKey) = self.get_x3dh_keys(username.to_string()).unwrap();
        let client_keys: ClientKeyCollection = ClientKeyCollection::from(x3dh_keys.0, x3dh_keys.1, x3dh_keys.2, x3dh_keys.3, x3dh_keys.4);
        Ok(Client::from(username.to_string(), communication, client_keys))
    }
}