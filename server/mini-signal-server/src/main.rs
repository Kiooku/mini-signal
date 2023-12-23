mod server;
mod database;

use database::{message_database, password_database::PasswordDatabase, x3dh_keys_database::X3DHDatabase};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use warp::Filter;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Duration;
use bytes::Bytes;
use warp::ws::WebSocket;
use crate::database::message_database::MessageDatabase;

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
        password: String,
    },
    LogIn { // Client to the Server
        username: String,
        password: String,
    },
    LogOut, // Client to the Server
    GetAllUsers,
    PublishX3DHInformation { // Sent when the user is created (Client to the Server)
        ik: [u8; 32],
        spk: [u8; 32],
        opk_bundle: Vec<[u8; 32]>,
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    UpdateX3DHSignedPreKey { // Client to the Server
        spk: [u8; 32],
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    SupplyX3DHOneTimePreKeyBundle { // Client to the Server (Server send a response to confirm that he received the message
        opk_bundle: Vec<[u8; 32]>,
    },
    GetUserPublicKeys { // Client to the Server (handle user does not exist)
        username: String,
    },
    SendMessage{ // Client to the Server
        username_receiver: String,
        header_encrypted: Vec<u8>,
        header_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        ek_sender: Option<[u8;32]>,
        opk_used: Option<[u8;32]>
    },
    /*
    Messages { // Server to the Client
        // TODO (Remove the id of the message when we send it to the user
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
        opk: Option<[u8; 32]>,
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
}

type Db = Arc<Mutex<HashMap<String, String>>>;

#[tokio::main]
async fn main() {
    // Server
    let db = Arc::new(Mutex::new(HashMap::new()));
    /*
    let heartbeat = warp::path("heartbeat")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let db = db.clone();
            ws.on_upgrade(move |socket| async move {
                // Handle the WebSocket connection
                handle_heartbeat(socket, db).await;
            })
        });*/

    let endpoint = warp::post()
        .and(warp::body::json())
        .and(warp::addr::remote())
        .map(move |body, addr| warp::reply::json(&action_handler(body, addr, &db.clone())));

    println!("Server started");

    //let routes = endpoint.or(heartbeat);

    warp::serve(endpoint)
        .tls()
        .cert_path("src/keys/cert.pem")
        .key_path("src/keys/key.rsa")
        .run(([127, 0, 0, 1], 6379)).await;
}
/*
async fn handle_heartbeat(socket: WebSocket, db: Db) {
    // Periodically send a heartbeat message and check for client responses
    let (mut tx, mut rx) = socket.split();
    let heartbeat_interval = Duration::from_secs(10);

    // Clone Arc<Mutex<HashMap<String, String>>> for use in the loop
    let db_clone = db.clone();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(heartbeat_interval).await;

            // Try sending a heartbeat message
            if let Err(_) = tx.send(warp::ws::Message::ping(Vec::new())).await {
                // If sending fails, assume the client has disconnected
                // Perform cleanup or logging as needed

                // Example: Remove user from the HashMap
                //let mut db = db_clone.lock().unwrap();
                //db.retain(|_, v| v != &rx.addr().unwrap().ip().to_string());
                println!("User seems to be disconnected");
                break;
            }
        }
    });
}
*/
fn action_handler(request: Action, ip_addr: Option<SocketAddr>, db: &Db) -> Response {
    println!("Get a request: {:?}", request);
    println!("Ip Address: {:?} ({:?})", ip_addr.unwrap().ip(), ip_addr.unwrap());
    println!("{:?}", db);
    // TODO Multiple database (passwords, X3DH keys, messages, user online) [sqlite, sqlite, sqlite, tokio Arc]

    // TODO check if my database can handle multiple connection
    let mut password_db: PasswordDatabase = match PasswordDatabase::new() {
        Ok(res) => res,
        Err(error) => panic!("{}", error),
    };

    let mut x3dh_db: X3DHDatabase = match X3DHDatabase::new() {
        Ok(res) => res,
        Err(error) => panic!("{}", error),
    };

    let mut message_db: MessageDatabase = match MessageDatabase::new() {
        Ok(res) => res,
        Err(error) => panic!("{}", error),
    };

    let result = match request {
        Action::NewUser {username, password} => {
            let user_exist: bool = match password_db.user_exist(username.clone()) {
                Ok(res) => res,
                Err(error) => panic!("{}", error),
            };
            if user_exist {
                return Response::ResponseStatus { success: false }
            }
            password_db.insert_user(&username, &password).expect("Database done?");
            Response::ResponseStatus { success: true }
        },
        Action::LogIn {username, password} => {
            let mut db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                return Response::ResponseStatus { success: false }
            }
            let password_valid: bool = match password_db.check_password(&username, password) {
                Ok(res) => res,
                Err(error) => panic!("{}", error),
            };
            if password_valid {
                db.insert(ip_addr.unwrap().to_string(), username);
                return Response::ResponseStatus { success: true }
            }
            Response::ResponseStatus { success: false }
        },
        Action::LogOut {} => {
            let mut db = db.lock().unwrap();
            if db.remove(&ip_addr.unwrap().to_string()).is_some() {
                return Response::ResponseStatus { success: true }
            }
            Response::ResponseStatus { success: false }
        },
        Action::GetAllUsers {} => {
            let db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                let user_list: Vec<String> = x3dh_db.get_all_users().unwrap();
                return Response::UserList { result: user_list }
            }
            // TODO handle in a better way
            Response::ResponseStatus { success: false }
        },
        Action::PublishX3DHInformation {ik, spk, opk_bundle, signature, verifying_key} => {
            // TODO Check if the response status is right when it's the first time that someone send the X3DH keys
            let db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                let current_username = db.get(&ip_addr.unwrap().to_string()).unwrap();

                if x3dh_db.user_exist(current_username).unwrap() { // User has already publish information (should not change ik)
                   return  Response::ResponseStatus { success: false }
                }

                match x3dh_db.insert_x3dh_keys(current_username, ik, spk, opk_bundle, signature, verifying_key) {
                    Ok(()) => return Response::ResponseStatus { success: true },
                    Err(error) => {
                        println!("{}", error);
                        return Response::ResponseStatus { success: false } },
                }
            }

            Response::ResponseStatus { success: false }
        },
        Action::UpdateX3DHSignedPreKey {spk, signature, verifying_key} => {
            // TODO Check if it has been updated sufficient days ago (add in the database) [Or do it every week/month at a precise date for everyone]
            let db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                let current_username = db.get(&ip_addr.unwrap().to_string()).unwrap();

                if x3dh_db.user_exist(current_username).unwrap() { // Check if the user has sent the first X3DH keys
                    x3dh_db.update_spk(current_username, spk, signature, verifying_key).expect("Error updating spk");
                    return  Response::ResponseStatus { success: true }
                }
            }
            Response::ResponseStatus { success: false }
        },
        Action::SupplyX3DHOneTimePreKeyBundle {opk_bundle} => {
            let db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                let current_username = db.get(&ip_addr.unwrap().to_string()).unwrap();

                if x3dh_db.user_exist(current_username).unwrap() { // Check if the user has sent the first X3DH keys
                    x3dh_db.add_opk_bundle(current_username, opk_bundle).expect("Error inserting opk bundle");
                    return  Response::ResponseStatus { success: true }
                }
            }
            Response::ResponseStatus { success: false }
        },
        Action::GetUserPublicKeys {username} => {
            let db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                match x3dh_db.get_public_keys(username) {
                    Ok((ik, spk, opk, signature, verifying_key)) => {
                        if opk.is_some() {
                            x3dh_db.delete_opk_key(opk.unwrap()).expect("Error when opk deleted");
                        }
                        return Response::UserPublicKeys {
                            ik: ik,
                            spk: spk,
                            opk: opk,
                            signature: signature,
                            verifying_key: verifying_key,
                        };
                    },
                    Err(_) => return Response::ResponseStatus { success: false }
                }
            }
            // TODO handle in a better way
            Response::ResponseStatus { success: false }
        },
        Action::SendMessage { username_receiver, header_encrypted, header_nonce, ciphertext, nonce, ek_sender, opk_used} => {
            // TODO store message in the database if the user is offline, otherwise send to the user and check if the user has received the message
            let db = db.lock().unwrap();
            if db.contains_key(&ip_addr.unwrap().to_string()) {
                let sender_username = db.get(&ip_addr.unwrap().to_string()).unwrap();
                if x3dh_db.user_exist(&username_receiver).unwrap() && &username_receiver != sender_username {
                    if !db.values().any(|&username| username == username_receiver) {
                        message_db.add_message(&username_receiver, sender_username, header_encrypted, header_nonce, ciphertext, nonce, ek_sender, opk_used).expect("Add message to database failed");
                    } else {
                        // TODO send to the user and check that he/she receive it
                        println!("TODO: user connected and should receive your message")
                    }
                }
            }
            Response::ResponseStatus { success: false }
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