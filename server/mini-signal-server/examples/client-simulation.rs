use argon2::{password_hash::{
    PasswordHasher, SaltString
}, Argon2};
use serde::{Serialize, Deserialize};
use reqwest::{Client, Error};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "action")]
enum Action {
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
        opk_used: Option<[u8;32]>,
        ik_sender: Option<[u8;32]>
    },
}

#[derive(Debug, Deserialize)]
enum ServerResponse {
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
        messages: Option<Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<[u8;32]>, Option<[u8;32]>, Option<[u8;32]>)>>,
    },
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
    let mock_ik_sender: Option<[u8;32]> = Some([15u8;32]);

    // NewUser -> LogIn -> PublishX3DHInformation -> GetAllUsers -> GetUserPublicKeys (Boris) -> SendMessage (Boris) -> GetUserPublicKeys (Elliot) -> SendMessage (Elliot) -> Wait to receive the answer (Elliot) -> SupplyX3DHOneTimePreKeyBundle -> LogOut
    // NewUser -> LogIn -> PublishX3DHInformation -> GetAllUsers -> LogOut
    // Add test of multiple login
    let simulation_boris: Vec<Action> = vec![Action::NewUser { username: "Boris".to_string(), password: get_hash(&"siroB".to_string()) },
                                             Action::LogIn { username: "Boris".to_string(), password: get_hash(&"siroB".to_string()) },
                                             Action::PublishX3DHInformation { ik: mock_ik, spk: mock_spk, opk_bundle: mock_opk_bundle.clone(), signature: mock_signature, verifying_key: mock_verifying_key },
                                             Action::GetAllUsers,
                                             Action::GetMessages,
                                             Action::LogOut];

    // let random_bytes = rand::thread_rng().gen::<[u8; 32]>(); (https://qertoip.medium.com/how-to-generate-an-array-of-random-bytes-in-rust-ccf742a1afd5)
    let simulation_jack: Vec<Action> = vec![Action::NewUser { username: "Jack".to_string(), password: get_hash(&"kcaJ".to_string()) },
                                       Action::LogIn { username: "Jack".to_string(), password: get_hash(&"kcaJ".to_string()) },
                                       Action::PublishX3DHInformation { ik: mock_ik, spk: mock_spk, opk_bundle: mock_opk_bundle.clone(), signature: mock_signature, verifying_key: mock_verifying_key },
                                       Action::GetAllUsers,
                                       Action::GetMessages,
                                       Action::GetUserPublicKeys { username: "Jack".to_string() },
                                       Action::SendMessage { username_receiver: "Boris".to_string(), header_encrypted: mock_header_encrypted.clone(), header_nonce: mock_header_nonce.clone(), ciphertext: mock_ciphertext.clone(), nonce: mock_ciphertext_nonce.clone(), ek_sender: mock_ek_sender.clone(), opk_used: mock_opk_used.clone(), ik_sender: mock_ik_sender.clone() },
                                       Action::SendMessage { username_receiver: "Jack".to_string(), header_encrypted: mock_header_encrypted.clone(), header_nonce: mock_header_nonce.clone(), ciphertext: mock_ciphertext.clone(), nonce: mock_ciphertext_nonce.clone(), ek_sender: None, opk_used: None, ik_sender: None },
                                       //Action::SupplyX3DHOneTimePreKeyBundle { opk_bundle: vec![[73u8; 32]] },
                                       //Action::UpdateX3DHSignedPreKey { spk: mock_spk_update, signature: mock_signature_update, verifying_key: mock_verifying_key_update },
                                       // TODO add the missing actions
                                       Action::LogOut];


    // Create a reqwest client
    let client_boris = Client::builder()
        .danger_accept_invalid_certs(true) // For testing purpose (For production use a Valid TLS Certificate)
        .use_native_tls()
        .build()?;

    let client_jack = Client::builder()
        .danger_accept_invalid_certs(true) // For testing purpose (For production use a Valid TLS Certificate)
        .use_native_tls()
        .build()?;


    let simulation: Vec<(Client, Vec<Action>)> = vec!((client_boris, simulation_boris),
                                                      (client_jack, simulation_jack));

    // Send a POST request to the server
    for (client, data) in simulation {
        println!("Client X");
        for request_data in data {
            let response = post(&client, request_data).await?;
            get_result(response).await?;
        }
    }

    Ok(())
}

async fn post(client: &Client, data: Action) -> Result<reqwest::Response, Error> {
    // Send a POST request to the server
    let response = client
        .post("https://0.0.0.0:6379")
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

fn get_hash(password: &String) -> String {
    let salt: SaltString = match SaltString::from_b64("vRpg/cByxpn6m1L0ZPF5ew") { //SaltString::generate(&mut OsRng);
        Ok(salt) => salt,
        Err(error) => panic!("{}", error),
    };

    let argon2: Argon2 = Argon2::default();
    let hash: String = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(error) => panic!("{}", error),
    };
    hash
}