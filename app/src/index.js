const { invoke } = window.__TAURI__.tauri;
const loginButton = document.getElementById("login-btn");
const loginForm = document.getElementById("login-from");

loginButton.addEventListener("click", async () => {
    if (loginForm.checkValidity()) {
        let username = document.getElementById("username").value;
        let password = document.getElementById("password").value;
        let isValidCredential = await invoke("verify_credential", { username: username, password: password });
        if (isValidCredential) {
            localStorage.setItem('username', username);
            window.location.href = "main.html";
        } else {
            alert("Invalid login credential. Please try again."); // Alert not working on tauri
        }
    }

});