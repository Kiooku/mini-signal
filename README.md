# mini-signal

---

`mini-signal` is an incomplete implementation of [Signal](https://signal.org/), for learning purpose.

The goal of this project is to implement a visual interface and a server, allowing to simulate the one to one message functionality of Signal.

For that, I'll use the cryptographic algorithm develop in my [Cryptography-Notebook](https://github.com/Kiooku/Cryptography-Notebook) 
repository, [tokio](https://tokio.rs/) and [native-tls](https://github.com/sfackler/rust-native-tls) for the asynchronous server and [tauri](https://tauri.app/) 
for the user interface.

*Obviously, don't use this application for real-world usage. Nothing has been reviewed by professionals and may include serious fault.*
*</br>However, it's a great tool for learning (feel free to use it to test some attacks or get a better understanding of a secure message application).*

*What's more, there's still a bit of work to be done to completely clean up the project, even if the result is quite decent and fully functional.*

**Keywords**: end-to-end messaging service, double ratchet, E2EE, X3DH, TCP, TLS, Signal, SQLite, AES-GCM-SIV, AEAD,
Rust, Tauri, HTML, CSS, JS, Security, Privacy, Concurrency, Tokio

## Table of content

1. [How to install mini-signal](#how-to-install-mini-signal)
2. [How to deploy the server](#how-to-deploy-the-server)
3. [Implementation details](#implementation-details)
   - [Cryptography](#cryptography)
   - [Server](#server)
   - [Client](#client)
   - [Conclusion](#conclusion)
4. [Resources](#resources)

## How to install mini-signal

Start the server before starting the client: `cargo run` in `mini-signal-server`.

You can simply run `cargo tauri dev` in `mini-signal`, to launch the app on dev mode.

Otherwise, if you want to build an executable of the app, I'll suggest you to follow the [guide on the Tauri website](https://tauri.app/v1/guides/building/cross-platform/).

## How to deploy the server

To initialize `cert.pem` and `key.rsa` in the keys folder of `mini-signal-server`, run the following command:

`openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout src/keys/key.rsa -out src/keys/cert.pem -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"`

> **Note**: Make sure that `cert.pem` and `key.rsa` are located in the `keys` folder.

Then run: `cargo run`, you should see the message *"Server started"*.

## Implementation details

### Cryptography

The end-to-end encryption is done using the [double ratchet algorithm with header encryption](https://github.com/Kiooku/Cryptography-Notebook/tree/main/E2EE/double-ratchet-with-header-encryption) initialize with the [X3DH](https://github.com/Kiooku/Cryptography-Notebook/tree/main/AsymmetricCiphers/x3dh) protocol.

All the rust implementation of these two protocol can be seen on my [Cryptography-Notebook repository](https://github.com/Kiooku/Cryptography-Notebook/tree/main/E2EE).

[`native-tls`](https://github.com/sfackler/rust-native-tls) crate is used for TLS.

[Argon2id](https://en.wikipedia.org/wiki/Argon2)  hash function is used to store the passwords.

### Server

The server use a TCP over TLS connection to communicate with the client.

All the server is done in Rust using the [`tokio`](https://tokio.rs/), [`warp`](https://github.com/seanmonstar/warp) and [`native-tls`](https://github.com/sfackler/rust-native-tls) crate.

The TCP over TLS connection can be replaced with [XMPP](https://xmpp.org/), but I wanted to make a Rust project and XMPP 
does not have a reliable crate, and I wanted to make the server using Rust for learning purpose.

Users must identify themselves before sending or collecting data.

The server deal with three sqlite databases. I used [`rusqlite`](https://github.com/rusqlite/rusqlite) to interact with them. 

**Message database**: Use to store messages when the user is not connected to the server. Messages are deleted once the user has retrieved them.

**X3DH keys database**: Use to store the X3DH keys used to initiate E2EE.

**Password database**: Store user password using [`argon2id`](https://docs.rs/rust-argon2/latest/argon2/) hash function to follow [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

All possible actions that the client can perform with the server are described in the `Action` enumeration. 
And all possible responses in the `Response` enumeration in `main.rs`.

### Client

> **Note**
> 
> The client front-end is made using vanilla HTML, CSS and JS.
> 
> Tauri does not support some CSS function which modify slightly the final render from a browser. 
> 
> *e.g. `overflow-anchor: auto` and `backdrop-filter: saturate(120%) blur(14px);` are not supported.*

Three database on the client side (TODO)
#### TODO

**Note for later**: `overflow-anchor: auto` and `backdrop-filter: saturate(120%) blur(14px);` not supported on Tauri 
(which slightly change the quality of the result).

### Conclusion

#### TODO talk about the vulnerability if someone hack the client or the server.

## Resources
- https://signal.org/docs/
- https://tokio.rs/tokio/tutorial
- https://tauri.app/v1/guides/