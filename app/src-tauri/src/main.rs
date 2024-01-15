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
use once_cell::sync::Lazy;
use crate::communication::client::Client;
use crate::communication::key_collection::ServerKeyCollection;
use crate::database::message_database::MessageDatabase;

lazy_static! {
    static ref CLIENT: MiniSignalClient = {
        match MiniSignalClient::new() {
            Ok(c) => c,
            Err(error) => panic!("{}", error),
        }
    };
}

static MESSAGE_DATABASE: Lazy<Arc<Mutex<Option<MessageDatabase>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(None))
});

fn initialize_database(username: &str) {
    let mut database = MESSAGE_DATABASE.lock().unwrap();
    if database.is_none() {
        *database = Some(MessageDatabase::new(username).expect("Failed to initialize the database"));
    }
}

// TODO create a get client result (remove code duplication)

#[tauri::command]
async fn verify_credential(username: &str, password: &str) -> Result<bool, String> {
    let post_info = CLIENT.post(Action::LogIn {
        username: username.to_string(),
        password: get_hash(&password.to_string()),
    }).await;

    match post_info {
        Ok(info) => {
            match CLIENT.get_result(info).await {
                Ok(ServerResponse::ResponseStatus { success }) => {
                    if success { initialize_database(username) };
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
    let post_info = CLIENT.post(Action::NewUser {
        username: username.to_string(),
        password: get_hash(&password.to_string()),
    }).await;

    match post_info {
        Ok(info) => {
            match CLIENT.get_result(info).await {
                Ok(ServerResponse::ResponseStatus { success }) => {
                    if success {
                        // TODO create a client database protected by the same password to enter to the server
                        // TODO modify the communication::client::Client to allow the creation of a client from known data
                        let _ = CLIENT.post(Action::LogIn { // Need to be log in to send the X3DH information
                            username: username.to_string(),
                            password: get_hash(&password.to_string()),
                        }).await; // TODO can handle if the login work or not

                        // TODO the X3DH can be better handle (for example if the user is well register but the X3DH fail, the user will never be able to register
                        let mut current_client: Client = Client::new(username.to_string());
                        let key_collection_for_server: ServerKeyCollection = current_client.get_server_keys();
                        let post_x3dh_info = CLIENT.post(Action::PublishX3DHInformation {
                            ik: key_collection_for_server.get_ik().to_bytes(),
                            spk: key_collection_for_server.get_spk().to_bytes(),
                            opk_bundle: key_collection_for_server.get_opk_bundle_bytes(),
                            signature: key_collection_for_server.get_signature_to_bytes(),
                            verifying_key: key_collection_for_server.get_verifying_key().to_bytes() }).await;

                        let x3dh_res = match post_x3dh_info {
                            Ok(info) => {
                                match CLIENT.get_result(info).await {
                                    Ok(ServerResponse::ResponseStatus { success }) => Ok(success),
                                    Err(error) => Err(format!("Error during X3DH publication: {}", error)),
                                    Ok(test) => Ok(false),
                                }
                            },
                            Err(error) => Err(format!("Error during X3DH publication: {}", error)),
                        };
                        let _ = CLIENT.post(Action::LogOut).await; // TODO can handle if the logout work or not
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
    let result = CLIENT.post(Action::LogOut).await;

    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("{}", error)), // TODO cancel the close event and say to try again
    }
}

#[tauri::command]
async fn get_all_users() -> Result<Vec<String>, String> {
    let post_info = CLIENT.post(Action::GetAllUsers).await;

    match post_info {
        Ok(info) => {
            match CLIENT.get_result(info).await {
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
    let post_info = CLIENT.post(Action::GetMessages).await;

    match post_info {
        Ok(info) => {
            match CLIENT.get_result(info).await {
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

// TODO maybe that I don't need this function to be a tauri::command and can just use it in the send_message
#[tauri::command]
async fn get_user_public_key(username: &str) -> Result<Vec<([u8;32], [u8;32], Option<[u8;32]>, [[u8;32]; 2], [u8;32])>, String> {
    let post_info = CLIENT.post(Action::GetUserPublicKeys { username: username.to_string() }).await;

    match post_info {
        Ok(info) => {
            match CLIENT.get_result(info).await {
                Ok(ServerResponse::UserPublicKeys { ik, spk, opk, signature, verifying_key }) => Ok(vec![(ik, spk, opk, signature, verifying_key)]),
                Err(error) => Err(format!("Error when collecting user public keys: {}", error)),
                Ok(server_response) => Err(format!("Error when collecting user public keys (bad server response): {:?}", server_response)),
            }
        },
        Err(error) => Err(format!("Error when collecting user public keys (post_info): {}", error)),
    }
}

#[tauri::command]
async fn send_message(username_sender: &str, username_receiver: &str, message: &str) -> Result<(), String> {
    // TODO add the E2EE and TCP over TLS communication
    // run the following command to avoid the app to reload when interacting with the database
    // (probably because we modify MESSAGE_DATABASE that make the app to reload): cargo tauri dev --no-watch

    let mut database_guard = MESSAGE_DATABASE.lock().unwrap();
    if let Some(mut database) = database_guard.take() {
        database.insert_message(username_sender, username_receiver, message)
            .expect("Message insertion in database raised an error");

        *database_guard = Some(database);
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
        .invoke_handler(tauri::generate_handler![verify_credential, register, log_out, get_all_users, get_messages, get_user_public_key, send_message, load_messages])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    Ok(())
}
