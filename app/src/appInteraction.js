const themeToggleBtn = document.getElementById('toggle');
const body = document.body;

themeToggleBtn.addEventListener('click', () => {
    // Toggle between light and dark themes
    if (body.getAttribute('data-theme') === 'light') {
        body.setAttribute('data-theme', 'dark');
    } else {
        body.setAttribute('data-theme', 'light');
    }
});

const sendBtn = document.getElementById("btnSend");
const messageInput = document.getElementById("message-input")
const messagesWrapper = document.getElementById("messages");

sendBtn.addEventListener("click", () => {
    if (messageInput.textContent.length > 0) {
        let newMessage = document.createElement('div');
        if (messagesWrapper.childElementCount - 1 === 0) {
            newMessage.className = "container yours first";
        } else {
            newMessage.className = "container yours";
        }

        let lines = messageInput.innerText.split('\n');
        lines.forEach(line => {
            newMessage.appendChild(document.createTextNode(line));
            newMessage.appendChild(document.createElement('br'));
        });

        newMessage.removeChild(newMessage.lastChild);

        messagesWrapper.insertBefore(newMessage, messagesWrapper.children[messagesWrapper.childElementCount - 1]);
        messageInput.textContent = "";
        searchMessage();
    }
});

function onUserSelected(userClicked) {
    let userPreviouslySelected = document.getElementById("selected");
    userPreviouslySelected.removeAttribute("id");
    userClicked.setAttribute("id", "selected");
    let currentFriendFirstLetter = document.getElementById("currentFriendFirstLetter");
    currentFriendFirstLetter.textContent = userClicked.getElementsByTagName("span")[0].textContent;
    let currentFriendName = document.getElementById("currentFriendName");
    currentFriendName.textContent = userClicked.getElementsByTagName("p")[0].textContent;
}

function searchUser() {
    let searchBar = document.getElementById("searchBarUser");
    let filter = searchBar.value.toUpperCase();
    Array.from(document.querySelectorAll('.user')).forEach(function(user) {
        if (user.getElementsByTagName("p")[0].textContent.toUpperCase().indexOf(filter) > -1) {
            user.style.display = "";
        } else {
            user.style.display = "none";
        }
    });
}

let currentMessageFoundNumber = document.getElementById("currentMessageFoundNumber");
let nbMessagesFound = document.getElementById("nbMessagesFound");
const upMessageBtn = document.getElementById("up");
const downMessageBtn = document.getElementById("down");
let messagesFound = [];

function searchMessage() {
    if (event.key === 'Enter' && currentMessageFoundNumber.textContent !== nbMessagesFound.textContent) {
        nextMessage();
    } else {
        messagesFound = [];
        let searchBar = document.getElementById("searchBarMessage");
        let filter = searchBar.value.toUpperCase();
        let messageFound = document.getElementById("messagesFound");
        if (filter.length > 0) {
            messageFound.style.visibility = "visible";
        } else {
            messageFound.style.visibility = "hidden";
        }

        Array.from(document.querySelectorAll('.container')).forEach(function(message) {
            message.removeAttribute("id"); // Reset highlight
            if (message.textContent.toUpperCase().indexOf(filter) > -1) {
                messagesFound.push(message);
            }
        });

        if (messagesFound.length > 0 && filter.length > 0) {
            messagesFound[0].scrollIntoView({
                behavior: 'smooth',
                block: 'center',
            });
            messagesFound[0].setAttribute("id", "highlight")
        } else if (messagesFound.length > 0) {
            messagesFound[0].removeAttribute("id");
        }

        currentMessageFoundNumber.textContent = messagesFound.length > 0 ? "1" : "0";
        nbMessagesFound.textContent = messagesFound.length.toString();
        downMessageBtn.style.borderColor = messagesFound.length > 0 ? "var(--text)" : "grey";
        upMessageBtn.style.borderColor = currentMessageFoundNumber.textContent === "0" || currentMessageFoundNumber.textContent === "1" ? "grey" : "var(--text)";
    }
}

function nextMessage() {
    if (parseInt(currentMessageFoundNumber.textContent) < parseInt(nbMessagesFound.textContent)) {
        currentMessageFoundNumber.textContent = (parseInt(currentMessageFoundNumber.textContent) + 1).toString();
        messagesFound[parseInt(currentMessageFoundNumber.textContent) - 1].scrollIntoView({
            behavior: 'smooth',
            block: 'center',
        });
        messagesFound[parseInt(currentMessageFoundNumber.textContent) - 2].removeAttribute("id");
        messagesFound[parseInt(currentMessageFoundNumber.textContent) - 1].setAttribute("id", "highlight")
    }
    updateMessageBtnColor();
}

downMessageBtn.addEventListener("click", () => {
    nextMessage();
});

upMessageBtn.addEventListener("click", () => {
    if (parseInt(currentMessageFoundNumber.textContent) > 1) {
        currentMessageFoundNumber.textContent = (parseInt(currentMessageFoundNumber.textContent) - 1).toString();
        messagesFound[parseInt(currentMessageFoundNumber.textContent) - 1].scrollIntoView({
            behavior: 'smooth',
            block: 'center',
        });
        messagesFound[parseInt(currentMessageFoundNumber.textContent)].removeAttribute("id");
        messagesFound[parseInt(currentMessageFoundNumber.textContent) - 1].setAttribute("id", "highlight")
    }
    updateMessageBtnColor();
});

function updateMessageBtnColor() {
    if (currentMessageFoundNumber.textContent === nbMessagesFound.textContent) {
        downMessageBtn.style.borderColor = "grey";
    } else {
        downMessageBtn.style.borderColor = "var(--text)";
    }

    if (currentMessageFoundNumber.textContent === "0" || currentMessageFoundNumber.textContent === "1") {
        upMessageBtn.style.borderColor = "grey";
    } else {
        upMessageBtn.style.borderColor = "var(--text)";
    }
}

// JS for Tauri app
const { invoke } = window.__TAURI__.tauri;
const { TauriEvent } = window.__TAURI__.event;
const { appWindow } = window.__TAURI__.window;
appWindow.listen(TauriEvent.WINDOW_CLOSE_REQUESTED, async () => {
    await invoke("log_out");
    appWindow.close();
});