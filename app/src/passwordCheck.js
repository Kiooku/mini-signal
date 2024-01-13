let username = document.getElementById("username");
let password = document.getElementById("password");
let confirm_password = document.getElementById("confirm-password");
let registerBtn = document.getElementById("register-btn");
let registerForm = document.getElementById("register-form");

function checkPassword() {
    if (password.value !== confirm_password.value) {
        confirm_password.setCustomValidity("Passwords don't match");
        return false;
    }
    confirm_password.setCustomValidity("");
    return true;
}

// JS for Tauri app
const { invoke } = window.__TAURI__.tauri;
registerBtn.addEventListener("click", async function(event) {
    confirm_password.reportValidity();
    password.reportValidity();
    username.reportValidity();
    if (checkPassword() && registerForm.checkValidity()) {
        let isValidCredential = await invoke("register", { username: username.value, password: password.value });
        if (isValidCredential) {
            location.href = "index.html"
        } else {
            event.preventDefault();
            alert("Error during registration: Password or username invalid. Please try again.");
        }
    }

});