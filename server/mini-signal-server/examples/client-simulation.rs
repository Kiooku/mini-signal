use serde::{Serialize, Deserialize};
use reqwest::{Client, Error};
use x25519_dalek::PublicKey;

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
    LogOut, // Replace logout with tcp connection stopped
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
}

#[derive(Debug, Deserialize)]
enum ServerResponse {
    UserList { result: Vec<String> },
    ResponseStatus { success: bool },
    UserPublicKeys { // Server to the Client
        ik: [u8; 32],
        spk: [u8; 32],
        opk: Option<[u8; 32]>,
        signature: [[u8; 32]; 2], // [r_bytes, s_bytes]
        verifying_key: [u8; 32],
    },
    /*
    Messages { // Server to the Client
        // TODO
    },*/
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    // Create JSON data
    let mock_ik: [u8; 32] = [0u8; 32];
    let mock_spk: [u8; 32] = [1u8; 32];
    let mock_opk_bundle: Vec<[u8; 32]> = vec!([0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
    let mock_signature: [[u8; 32]; 2] = [[2u8; 32], [3u8; 32]];
    let mock_verifying_key: [u8; 32] = [4u8; 32];
    let mock_spk_update: [u8; 32] = [23u8; 32];
    let mock_signature_update: [[u8; 32]; 2] = [[24u8; 32], [31u8; 32]];
    let mock_verifying_key_update: [u8; 32] = [42u8; 32];
    let mock_header_encrypted: Vec<u8> = vec![64u8; 32];
    let mock_header_nonce: Vec<u8> = vec![32u8; 32];
    let mock_ciphertext: Vec<u8> = vec![11u8; 32];
    let mock_ciphertext_nonce: Vec<u8> = vec![12u8; 32];
    let mock_ek_sender: Option<[u8;32]> = Some([13u8; 32]);
    let mock_opk_used: Option<[u8;32]> = Some([14u8; 32]);
    // Action::PublishX3DHInformation { ik: mock_ik, spk: mock_spk, opk_bundle: mock_opk_bundle, signature: mock_signature, verifying_key: mock_verifying_key},

    // NewUser -> LogIn -> PublishX3DHInformation -> GetAllUsers -> GetUserPublicKeys -> SendMessage -> Receive a message -> SupplyX3DHOneTimePreKeyBundle -> LogOut
    // LogIn -> GetAllUsers -> GetMessages -> SendMessage -> LogOut
    // Add test of multiple login, update spk and opk
    /*let simulation: Vec<Action> = vec![Action::NewUser {username: "Jack".to_string(), password: "kcaJ".to_string()},
                                       Action::LogIn {username: "Boris".to_string(), password: "siroB".to_string()},
                                       Action::LogIn {username: "Jack".to_string(), password: "kcaJ".to_string()},
                                       Action::LogIn {username: "Jack".to_string(), password: "kcaJ".to_string()},
                                       Action::LogOut,
                                       Action::LogIn {username: "Jack".to_string(), password: "kcaJ".to_string()},
                                       Action::GetAllUsers];*/
    let simulation: Vec<Action> = vec![Action::NewUser {username: "Jack".to_string(), password: "kcaJ".to_string()},
                                       Action::LogIn {username: "Jack".to_string(), password: "kcaJ".to_string()},
                                       Action::PublishX3DHInformation { ik: mock_ik, spk: mock_spk, opk_bundle: mock_opk_bundle, signature: mock_signature, verifying_key: mock_verifying_key},
                                       Action::GetAllUsers,
                                       Action::GetUserPublicKeys { username: "Jack".to_string() },
                                       Action::SendMessage { username_receiver: "Boris".to_string(), header_encrypted: mock_header_encrypted, header_nonce: mock_header_nonce, ciphertext: mock_ciphertext, nonce: mock_ciphertext_nonce, ek_sender: mock_ek_sender, opk_used: mock_opk_used },
                                       //Action::SupplyX3DHOneTimePreKeyBundle { opk_bundle: vec![[73u8; 32]] },
                                       //Action::UpdateX3DHSignedPreKey { spk: mock_spk_update, signature: mock_signature_update, verifying_key: mock_verifying_key_update },
                                       // TODO add the missing actions
                                       Action::LogOut];

    // Create a reqwest client
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // For testing purpose (For production use a Valid TLS Certificate)
        .use_native_tls()
        .build()?;

    // Send a POST request to the server
    for request_data in simulation {
        let response = post(&client, request_data).await?;
        get_result(response).await?;
    }

    Ok(())
}

async fn post(client: &Client, data: Action) -> Result<reqwest::Response, Error> {
    // Send a POST request to the server
    let response = client
        .post("https://127.0.0.1:6379")
        .json(&data)
        .send()
        .await?;

    Ok(response)
}

async fn get_result(response: reqwest::Response) -> Result<(), Error> {
    // Ensure the server returned a success status code (2xx)
    if response.status().is_success() {
        // Parse the JSON response
        let result: ServerResponse = response.json().await?;
        println!("Server response: {:?}", result);
    } else {
        eprintln!("Server returned an error: {:?}", response);
    }

    Ok(())
}