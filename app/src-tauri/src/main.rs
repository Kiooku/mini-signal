// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod hash;
mod tcp_client;
mod communication;
mod double_ratchet;
mod x3dh;

use std::iter::successors;
use std::thread::current;
use lazy_static::lazy_static;
use tauri::Manager;
use serde::{Deserialize, Serialize};
use hash::get_hash;
use tcp_client::{MiniSignalClient, Action, ServerResponse};
use communication::client;
use crate::communication::client::Client;
use crate::communication::key_collection::ServerKeyCollection;

lazy_static! {
    static ref CLIENT: MiniSignalClient = {
        match MiniSignalClient::new() {
            Ok(c) => c,
            Err(error) => panic!("{}", error),
        }
    };
}

// TODO create a get client result (remove code duplication)

#[tauri::command]
async fn verify_credential(username: &str, password: &str) -> Result<bool, String> {
    println!("username: {}; password: {}", username, get_hash(&password.to_string()));
    let post_info = CLIENT.post(Action::LogIn {
        username: username.to_string(),
        password: get_hash(&password.to_string()),
    }).await;

    match post_info {
        Ok(info) => {
            match CLIENT.get_result(info).await {
                Ok(ServerResponse::ResponseStatus { success }) => Ok(success),
                Err(error) => Err(format!("Error during login: {}", error)),
                _ => Ok(false),
            }
        },
        Err(error) => Err(format!("Error during login (post_info): {}", error)),
    }
}

#[tauri::command]
async fn register(username: &str, password: &str) -> Result<bool, String> {
    println!("username: {}; password: {}", username, get_hash(&password.to_string()));
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
    /*match result {
        Ok(res) => {
            let server_res = CLIENT.get_result(res).await;
            println!("{:?}", server_res);
            Ok(true) }, // TODO replace with the return value
        Err(error) => Err(format!("{}", error)),
    }*/
}

#[tauri::command]
async fn log_out() -> Result<(), String> {
    let result = CLIENT.post(Action::LogOut).await;

    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("{}", error)), // TODO cancel the close event and say to try again
    }
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![verify_credential, register, log_out])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    Ok(())
}
