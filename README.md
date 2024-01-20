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
> 
> For example, some messages are not displayed when the password does not match in the registration page *(further work to improve the user experience with Tauri constraints).*.

Two database on the client side:
1. Double Ratchet database:
   1. **Double Ratchet** table: Store the state of the double ratchet for each communication.
   2. **X3DH**: Store the X3DH keys of the client.
   3. **OPK Bundle**: Store the opk keys of the client.
2. **Messages** database: Store the message decrypted of the user.

> **Note**
> 
> To increase client-side security, it would be preferable to encrypt each database with a password *(the same as the one used to connect to the server)*.
> 
> However, as far as I know, rusqlite doesn't allow this, and I'd have to use another crate. This may be a project update for later.

Functionalities:
- Light and dark mode
- Search user
- Search message

Messages are gathered every 5 seconds on the server, so it's not instant E2EE encryption, but there is a certain delay. 
The switch to instant E2EE is a future application update.

### Conclusion

The aim of this project was to see the complexity of creating a secure messaging application prototype. 
Moreover, it allowed me to use my [X3DH](https://github.com/Kiooku/Cryptography-Notebook/tree/main/AsymmetricCiphers/x3dh) and [double ratchet algorithm](https://github.com/Kiooku/Cryptography-Notebook/tree/main/E2EE/double-ratchet-with-header-encryption) in a real world context.
In addition, it's a great opportunity to bring together most of the knowledge I have in [cryptography](https://github.com/Kiooku/Cryptography-Notebook) and computer science *(Database management, server, front-end, concurrent programming...)*

This is my first major project in rust and my first application in tauri. So I've learned a lot during this project. 
It's still an MVP and the project should be cleaned up in several points to get closer to a secure messaging application like Signal.

This project was carried out during my winter break. 
Features such as the management of message encryption sessions in an asynchronous and multi-device setting *[(Sesame algorithm)](https://signal.org/docs/specifications/sesame/)*, or private group system [(Zero-knowledge groups)](https://eprint.iacr.org/2019/1416.pdf),  could be implemented later, depending on my learning journey.

## Resources
- https://signal.org/docs/
- https://tokio.rs/tokio/tutorial
- https://tauri.app/v1/guides/