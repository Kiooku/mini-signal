// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod hash;
mod tcp_client;
mod communication;
mod double_ratchet;
mod x3dh;
mod database;

use lazy_static::lazy_static;
use tauri::Manager;
use serde::{Deserialize, Serialize};
use hash::get_hash;
use tcp_client::{MiniSignalClient, Action, ServerResponse};
use std::sync::{Arc, Mutex};
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::{Signature, VerifyingKey};
use once_cell::sync::Lazy;
use x25519_dalek::PublicKey;
use crate::communication::client::Client;
use crate::communication::key_collection::ServerKeyCollection;
use crate::communication::message::{Ciphertext, HeaderHE};
use crate::database::double_ratchet_database::DoubleRatchetDatabase;
use crate::database::message_database::MessageDatabase;

// run the following command to avoid the app to reload when interacting with the database: cargo tauri dev --no-watch
// (probably because we modify MESSAGE_DATABASE that make the app to reload when it's on the dev mode)

lazy_static! {
    static ref TCP_CLIENT: MiniSignalClient = {
        match MiniSignalClient::new() {
            Ok(c) => c,
            Err(error) => panic!("{}", error),
        }
    };
}

static MESSAGE_DATABASE: Lazy<Arc<Mutex<Option<MessageDatabase>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(None))
});

static DOUBLE_RATCHET_DATABASE: Lazy<Arc<Mutex<Option<DoubleRatchetDatabase>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(None))
});

static DOUBLE_RATCHET_CLIENT: Mutex<Option<Client>> = Mutex::new(None);

fn initialize_database(username: &str) {
    let mut message_database = MESSAGE_DATABASE.lock().unwrap();
    if message_database.is_none() {
        *message_database = Some(MessageDatabase::new(username).expect("Failed to initialize the message database"));
    }
    let mut double_ratchet_database = DOUBLE_RATCHET_DATABASE.lock().unwrap();
    if double_ratchet_database.is_none() {
        *double_ratchet_database = Some(DoubleRatchetDatabase::new(username).expect("Failed to initialize the double ratchet database"));
    }
}

// TODO create a get client result (remove code duplication)

#[tauri::command]
async fn verify_credential(username: &str, password: &str) -> Result<bool, String> {
    let post_info = TCP_CLIENT.post(Action::LogIn {
        username: username.to_string(),
        password: get_hash(&password.to_string()),
    }).await;

    match post_info {
        Ok(info) => {
            match TCP_CLIENT.get_result(info).await {
                Ok(ServerResponse::ResponseStatus { success }) => {
                    if success {
                        initialize_database(username);
                        let mut double_ratchet_database_guard = DOUBLE_RATCHET_DATABASE.lock().unwrap();
                        if let Some(mut double_ratchet_database) = double_ratchet_database_guard.take() {
                            let current_client: Client = double_ratchet_database.load_client(username)
                                .expect("Double ratchet collection raised an error");

                            *DOUBLE_RATCHET_CLIENT.lock().unwrap() = Some(current_client);
                            *double_ratchet_database_guard = Some(double_ratchet_database);
                        } else {
                            // Should not happen, because database is initialized when log in
                            return Err("Double ratchet database not initialized".to_string());
                        }
                    }
                    Ok(success)
                },
                Err(error) => Err(format!("Error during login: {}", error)),
                _ => Ok(false),
            }
        },
        Err(error) => Err(format!("Error during login (post_info): {}", error)),
    }
}

#[tauri::command]
async fn register(username: &str, password: &str) -> Result<bool, String> {
    let post_info = TCP_CLIENT.post(Action::NewUser {
        username: username.to_string(),
        password: get_hash(&password.to_string()),
    }).await;

    match post_info {
        Ok(info) => {
            match TCP_CLIENT.get_result(info).await {
                Ok(ServerResponse::ResponseStatus { success }) => {
                    if success {
                        // TODO create a client database protected by the same password to enter to the server
                        let _ = TCP_CLIENT.post(Action::LogIn { // Need to be log in to send the X3DH information
                            username: username.to_string(),
                            password: get_hash(&password.to_string()),
                        }).await; // TODO can handle if the login work or not

                        // TODO the X3DH can be better handle (for example if the user is well register but the X3DH fail, the user will never be able to register
                        let mut current_client: Client = Client::new(username.to_string());
                        let key_collection_for_server: ServerKeyCollection = current_client.get_server_keys();
                        let post_x3dh_info = TCP_CLIENT.post(Action::PublishX3DHInformation {
                            ik: key_collection_for_server.get_ik().to_bytes(),
                            spk: key_collection_for_server.get_spk().to_bytes(),
                            opk_bundle: key_collection_for_server.get_opk_bundle_bytes(),
                            signature: key_collection_for_server.get_signature_to_bytes(),
                            verifying_key: key_collection_for_server.get_verifying_key().to_bytes() }).await;

                        let x3dh_res = match post_x3dh_info {
                            Ok(info) => {
                                match TCP_CLIENT.get_result(info).await {
                                    Ok(ServerResponse::ResponseStatus { success }) => {
                                        // Store the client information on the client side
                                        let mut temp_double_ratchet_database: DoubleRatchetDatabase = DoubleRatchetDatabase::new(username).unwrap();
                                        temp_double_ratchet_database.insert_client(current_client).expect("Error when inserting a new client");

                                        Ok(success)
                                    },
                                    Err(error) => Err(format!("Error during X3DH publication: {}", error)),
                                    Ok(test) => Ok(false),
                                }
                            },
                            Err(error) => Err(format!("Error during X3DH publication: {}", error)),
                        };
                        let _ = TCP_CLIENT.post(Action::LogOut).await; // TODO can handle if the logout work or not
                        if x3dh_res.is_ok() {
                            return Ok(x3dh_res.unwrap())
                        }
                    }
                    Ok(success)
                },
                Err(error) => Err(format!("Error during register: {}", error)),
                _ => Ok(false),
            }
        },
        Err(error) => Err(format!("Error during register (post_info): {}", error)),
    }
}

#[tauri::command]
async fn log_out() -> Result<(), String> {
    let result = TCP_CLIENT.post(Action::LogOut).await;

    // TODO store the data in the client database (double_ratchet)
    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("{}", error)), // TODO cancel the close event and say to try again
    }
}

#[tauri::command]
async fn get_all_users() -> Result<Vec<String>, String> {
    let post_info = TCP_CLIENT.post(Action::GetAllUsers).await;

    match post_info {
        Ok(info) => {
            match TCP_CLIENT.get_result(info).await {
                Ok(ServerResponse::UserList { result }) => Ok(result),
                Err(error) => Err(format!("Error when collecting all the users: {}", error)),
                Ok(server_response) => Err(format!("Error when collecting all the users (bad server response): {:?}", server_response)),
            }
        },
        Err(error) => Err(format!("Error when gathering all the users (post_info): {}", error)),
    }
}

#[tauri::command]
async fn get_messages() -> Result<Option<Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<[u8;32]>, Option<[u8;32]>)>>, String> {
    let post_info = TCP_CLIENT.post(Action::GetMessages).await;

    match post_info {
        Ok(info) => {
            match TCP_CLIENT.get_result(info).await {
                Ok(ServerResponse::Messages { success, new_messages, messages }) => {
                    if success && new_messages {
                        return Ok(Some(messages.unwrap()))
                    }
                    Ok(None)
                },
                Err(error) => Err(format!("Error when collecting messages: {}", error)),
                Ok(server_response) => Err(format!("Error when collection messages (bad server response): {:?}", server_response)),
            }
        },
        Err(error) => Err(format!("Error when collection all the messages (post_info): {}", error)),
    }
}

async fn get_user_public_key(username: &str) -> Result<ServerKeyCollection, String> {
    let post_info = TCP_CLIENT.post(Action::GetUserPublicKeys { username: username.to_string() }).await;

    match post_info {
        Ok(info) => {
            match TCP_CLIENT.get_result(info).await {
                Ok(ServerResponse::UserPublicKeys { ik, spk, opk, signature, verifying_key }) => {
                    let mut merged_signature: [u8; 64] = [0; 64]; // Initialize with zeros or any default value
                    merged_signature[0..32].copy_from_slice(&signature[0]);
                    merged_signature[32..].copy_from_slice(&signature[1]);
                    let user_public_keys: ServerKeyCollection = ServerKeyCollection::from(
                        PublicKey::from(ik), PublicKey::from(spk),
                        if opk.is_some() { vec![PublicKey::from(opk.unwrap())] } else { Vec::new() },
                        Signature::from(SignatureBytes::from(merged_signature)),
                        VerifyingKey::from_bytes(&verifying_key).unwrap()
                    );
                    Ok(user_public_keys)
                },
                Err(error) => Err(format!("Error when collecting user public keys: {}", error)),
                Ok(server_response) => Err(format!("Error when collecting user public keys (bad server response): {:?}", server_response)),
            }
        },
        Err(error) => Err(format!("Error when collecting user public keys (post_info): {}", error)),
    }
}


#[tauri::command]
async fn send_message(username_sender: &str, username_receiver: &str, message: &str) -> Result<(), String> {
    // Encrypt the message using double ratchet
    let receiver_public_keys: ServerKeyCollection = get_user_public_key(username_receiver).await.unwrap();
    let double_ratchet_res;

    {
        let mut double_ratchet_client_guard = DOUBLE_RATCHET_CLIENT.lock().unwrap();
        double_ratchet_res = double_ratchet_client_guard.as_mut().unwrap().send_message(&username_receiver.to_string(), message.as_bytes(), &receiver_public_keys).unwrap();
    }

    let mut current_ek: Option<[u8;32]> = None;
    let mut current_opk: Option<[u8;32]> = None;
    if let Some((ek, opk)) = double_ratchet_res.0 {
        current_ek = Some(ek.to_bytes());
        current_opk = opk.map(|pk| pk.to_bytes());
    }
    let post_info = TCP_CLIENT.post(Action::SendMessage {
        username_receiver: username_receiver.to_string(),
        header_encrypted: double_ratchet_res.1.0.get_ciphertext(),
        header_nonce: double_ratchet_res.1.0.get_nonce(),
        ciphertext: double_ratchet_res.1.1.get_ciphertext(),
        nonce: double_ratchet_res.1.1.get_ciphertext(),
        ek_sender: current_ek,
        opk_used: current_opk
    }).await;

    match post_info {
        Ok(info) => {
            match TCP_CLIENT.get_result(info).await {
                Ok(ServerResponse::ResponseStatus { success }) => {
                    if !success {
                        //todo!();
                        println!("TODO, implement an error in the success when sending a message: {}", success);
                        // Signal the user that the message has not been sent (modify the database to store a bool if the message has been sent or not)
                    }
                },
                Err(error) => return Err(format!("Error when sending message: {}", error)),
                Ok(server_response) => return Err(format!("Error when collecting sending message status (bad server response): {:?}", server_response)),
            }
        },
        Err(error) => return Err(format!("Error when sending messages (post_info): {}", error)),
    };

    // Store the message in the client database
    let mut message_database_guard = MESSAGE_DATABASE.lock().unwrap();
    if let Some(mut message_database) = message_database_guard.take() {
        message_database.insert_message(username_sender, username_receiver, message)
            .expect("Message insertion in database raised an error");

        *message_database_guard = Some(message_database);
    } else {
        // Should not happen, because database is initialized when log in
        return Err("Database not initialized".to_string());
    }


    Ok(())
}

#[tauri::command]
async fn load_messages(username_receiver: &str) -> Result<Vec<(String, String, String)>, String> {
    let mut database_guard = MESSAGE_DATABASE.lock().unwrap();
    if let Some(database) = database_guard.as_mut() {
        let res = database.get_messages_with(username_receiver)
            .expect("Message selection in database raised an error");

        Ok(res)
    } else {
        // Should not happen, because database is initialized when log in
        return Err("Database not initialized".to_string());
    }
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![verify_credential, register, log_out, get_all_users, get_messages, send_message, load_messages])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    Ok(())
}
