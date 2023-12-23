use crate::database::{message_database, password_database, x3dh_keys_database};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use warp::Filter;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use bytes::Bytes;

// https://rust-lang-nursery.github.io/rust-cookbook/database/sqlite.html
// https://www.makeuseof.com/working-with-sql-databases-in-rust/
// https://docs.rs/rusqlite/latest/rusqlite/
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
// https://docs.rs/argon2/latest/argon2/

// Docker part
// https://blog.devgenius.io/building-a-secure-websocket-server-with-rust-warp-in-docker-20e842d143af
// openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.rsa -out cert.pem
// https://jan.newmarch.name/NetworkProgramming/TLS/wrapper.html?general

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "action")]
enum Action {
    NewUser { // Client to the Server
        username: String,
        password: Vec<u8>,
    },
    LogIn { // Client to the Server
        username: String,
        password: Vec<u8>,
    },
    GetAllUsers,
    PublishX3DHInformation { // Sent when the user is created (Client to the Server) (TODO add a client authentication)
        ik: [u8; 32],
        spk: [u8; 32],
        opk_bundle: Vec<[u8; 32]>,
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    UpdateX3DHSignedPreKey { // Client to the Server (TODO add a client authentication)
        spk: [u8; 32],
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    SupplyX3DHOneTimePreKeyBundle { // Client to the Server (Server send a response to confirm that he received the message (TODO add a client authentication)
        opk_bundle: Vec<[u8; 32]>,
    },
    GetUserPublicKeys { // Client to the Server (handle user does not exist)
        username: String,
    },
    SendMessage{ // Client to the Server
        // TODO
    },
    /*
    Messages { // Server to the Client
        // TODO
    },*/
}
// Do we need a LogOut or the server can now if the host is not reachable (try twice and if not, then wait the next connection)

#[derive(Debug, Deserialize, Serialize)]
enum Response {
    UserList { result: Vec<String> },
    ResponseStatus { success: bool },
    UserPublicKeys { // Server to the Client
        ik: [u8; 32],
        spk: [u8; 32],
        opk: [u8; 32],
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
}

type Db = Arc<Mutex<HashMap<String, Bytes>>>;

#[tokio::main]
async fn main() {
    let db = Arc::new(Mutex::new(HashMap::new()));

    let endpoint = warp::post()
        .and(warp::body::json())
        .and(warp::addr::remote())
        .map(move |body, addr| warp::reply::json(&action_handler(body, addr, &db.clone())));

    println!("Server started");

    warp::serve(endpoint)
        .tls()
        .cert_path("../keys/cert.pem")
        .key_path("../keys/key.rsa")
        .run(([127, 0, 0, 1], 6379)).await;
}

fn action_handler(request: Action, ip_addr: Option<SocketAddr>, db: &Db) -> Response {
    println!("Get a request: {:?}", request);
    println!("Ip Address: {:?} ({:?})", ip_addr.unwrap().ip(), ip_addr.unwrap());
    println!("{:?}", db);
    // TODO Multiple database (passwords, X3DH keys, messages, user online) [sqlite, sqlite, sqlite, tokio Arc]
    let mut db = db.lock().unwrap();
    db.insert(ip_addr.unwrap().to_string(), Bytes::from("Value"));

    let result = match request {
        Action::NewUser {username, password} => {
            // TODO check if the user exist and if yes, return false otherwise true (password already hashed)
            Response::ResponseStatus { success: true }
        },
        Action::LogIn {username, password} => {
            // TODO check if the password match with the username (password already hashed)
            Response::ResponseStatus { success: true }
        },
        Action::GetAllUsers {} => {
            // TODO get the value from the db
            Response::UserList { result: vec!["User1".to_string(), "User2".to_string(), "UserN".to_string()] }
        },
        Action::PublishX3DHInformation {ik, spk, opk_bundle, signature, verifying_key} => {
            // TODO add in the database (check if the user has not already publish information)
            Response::ResponseStatus { success: true }
        },
        Action::UpdateX3DHSignedPreKey {spk, signature, verifying_key} => {
            // TODO Check if it has been updated sufficient days ago (add in the database)
            Response::ResponseStatus { success: true }
        },
        Action::SupplyX3DHOneTimePreKeyBundle {opk_bundle} => {
            // TODO Add in the database
            Response::ResponseStatus { success: true }
        },
        Action::GetUserPublicKeys {username} => {
            // TODO ask the database (if the user does not exist return empty vec
            Response::UserList { result: Vec::new() }
        },
        Action::SendMessage {} => {
            // TODO store message in the database if the user is offline, otherwise send to the user and check if the user has received the message
            Response::ResponseStatus { success: true }
        },
    };

    result
}

#[derive(Debug, Deserialize, Serialize)]
struct Request {
    user: String,
    #[serde(flatten)]
    action: Action,
}