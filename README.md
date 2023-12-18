# mini-signal

---

`mini-signal` is an incomplete implementation of [Signal](https://signal.org/), for learning purpose.

The goal of this project is to implement a visual interface and a docker, allowing to simulate the Signal application.

For that, I'll use the cryptographic algorithm develop in my [Cryptography-Notebook](https://github.com/Kiooku/Cryptography-Notebook) 
repository, [tokio](https://tokio.rs/) and [Docker](https://www.docker.com/) for the asynchronous  server and [tauri](https://tauri.app/) 
for the user interface.

*Obviously, don't use this application for real-world usage. Nothing has been reviewed by professionals and may include serious fault.*
*</br>However, it's a great tool for learning (feel free to use it to test some attacks or get a better understanding of a secure message application).*

## Table of content

1. [How to install mini-signal](#how-to-install-mini-signal)
2. [How to deploy the server](#how-to-deploy-the-server)
3. [Implementation details](#implementation-details)
   - [Cryptography](#cryptography)
   - [Server](#server)
   - [Client](#client)
4. [Resources](#resources)

### TODO create a sum up

## How to install mini-signal

### TODO

## How to deploy the server

### TODO

## Implementation details

### Cryptography

#### TODO talk about DoubleRatchetAlgorithm, X3DH

### Server

#### TODO

### Client

#### TODO

**Note for later**: `overflow-anchor: auto` and `backdrop-filter: saturate(120%) blur(14px);` not supported on Tauri 
(which slightly change the quality of the result).

## Resources
- https://signal.org/docs/
- https://tokio.rs/tokio/tutorial
- https://tauri.app/v1/guides/