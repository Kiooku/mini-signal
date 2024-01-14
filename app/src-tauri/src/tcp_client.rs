use serde::{Serialize, Deserialize};
use reqwest::{Client, Error};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "action")]
pub enum Action {
    NewUser {
        username: String,
        password: String,
    },
    LogIn {
        username: String,
        password: String,
    },
    LogOut, // Replace logout with tcp connection stopped
    GetAllUsers,
    GetMessages,
    PublishX3DHInformation { // Sent when the user is created (Client to the Server)
    ik: [u8; 32],
        spk: [u8; 32],
        opk_bundle: Vec<[u8; 32]>,
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    UpdateX3DHSignedPreKey {
        spk: [u8; 32],
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    SupplyX3DHOneTimePreKeyBundle {
        opk_bundle: Vec<[u8; 32]>,
    },
    GetUserPublicKeys { // Client to the Server (handle user does not exist)
        username: String,
    },
    SendMessage {
        username_receiver: String,
        header_encrypted: Vec<u8>,
        header_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        ek_sender: Option<[u8;32]>,
        opk_used: Option<[u8;32]>
    },
}

#[derive(Debug, Deserialize)]
pub enum ServerResponse {
    UserList { result: Vec<String> },
    ResponseStatus { success: bool },
    UserPublicKeys {
        ik: [u8; 32],
        spk: [u8; 32],
        opk: Option<[u8; 32]>,
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    Messages {
        success: bool,
        new_messages: bool,
        messages: Option<Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<[u8;32]>, Option<[u8;32]>)>>,
    },
}

pub struct MiniSignalClient {
    client: Client,
}

impl MiniSignalClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true) // For testing purpose (For production use a Valid TLS Certificate)
            .use_native_tls()
            .build()?;
        Ok(MiniSignalClient { client })
    }

    pub async fn post(&self, data: Action) -> Result<reqwest::Response, Error> {
        // Send a POST request to the server
        let response = self.client
            .post("https://0.0.0.0:6379")
            .json(&data)
            .send()
            .await?;

        Ok(response)
    }

    pub async fn get_result(&self, response: reqwest::Response) -> Result<ServerResponse, Error> {
        // Ensure the server returned a success status code (2xx)
        if !response.status().is_success() {
            eprintln!("Server returned an error: {:?}", response);
        } else {

        }

        let result: ServerResponse = response.json().await?;
        Ok(result)
    }
}