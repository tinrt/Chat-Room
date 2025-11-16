# Live Chat Room System – Socket Programming Project

This project implements a fully functional **multi-client chat room system** using **C**, **TCP sockets**, and **multi-threading**. It includes:

- A **multi-threaded C server**
- A **C client** with hidden password input
- A **user authentication system** with SHA-256 password hashing
- Real-time messaging and broadcasting
- Logging, join/leave notifications, and `/list` command
- An optional **Web UI** connected via a WebSocket ↔ TCP bridge

---

## 🚀 Features

### ✔ Core Features
- Multi-threaded server handling multiple clients concurrently  
- Real-time chat messaging  
- C client with receiver thread  
- Cross-platform support (Windows & Linux/macOS)  
- User authentication  
  - Registration  
  - Login  
  - Unique usernames  
  - Passwords stored as **SHA-256 hashes**  
- Join/leave notifications  
- `/list` command to show online users  
- Chat message logging (`chatlog.txt`)

### ✔ Optional / Extra Features
- Web browser chat interface (`index.html`)
- WebSocket ↔ TCP bridge (`ws_proxy.js`)
- Clean UI for browser-based chatting

---

## 📁 Project Structure

```
.
├── p1gxS.c           # C Server
├── p1gxC.c           # C Client
├── index.html        # Optional Web UI
├── ws_proxy.js       # WebSocket ↔ TCP bridge
├── users.db          # Automatically created on first run
├── chatlog.txt       # Generated log file
└── README.md
```

---

## 🧠 System Architecture

### 1. C Server
- Listens on port **9090**
- Spawns a thread for each client
- Stores usernames + sockets in synchronized arrays
- Handles:
  - Authentication  
  - Broadcasting  
  - Message logging  
  - Client removal  
  - Commands (e.g., `/list`)

### 2. C Client
- Connects to server and completes authentication dialogue
- Hides password input (Windows: `_getch()`, Linux/macOS: `termios`)
- Runs:
  - **Receiver thread** → prints messages from server  
  - **Main thread** → handles user input

### 3. Web UI (Optional)
Browser → WebSocket → `ws_proxy.js` → TCP → C server

---

## 🔐 Authentication

### Registration
- User chooses a unique username
- Password hashed using **SHA-256**
- Stored locally in `users.db`

### Login
- Server hashes input password and compares with stored hash
- Prevents duplicate login names
- Denies invalid credentials

---

## 🛠️ Compilation & Setup

### Linux/macOS

#### Server:
```bash
gcc -pthread -o server p1gxS.c
```

#### Client:
```bash
gcc -pthread -o client p1gxC.c
```

---

### Windows (MinGW)

#### Server:
```bash
gcc -o server.exe p1gxS.c -lws2_32
```

#### Client:
```bash
gcc -o client.exe p1gxC.c -lws2_32
```

---

## ▶️ Running the Programs

### 1. Start the Server
```bash
./server
```

Expected:
```
Server started on port 9090...
```

---

### 2. Start the Client
```bash
./client
```

Authentication flow:
```
Do you have an account? (yes/no):
```

Commands:
- `/list` → show online users  
- `exit` → disconnect  

---

## 🌐 Running the Web UI (Optional)

### 1. Install WebSocket dependency:
```bash
npm install ws
```

### 2. Start WebSocket bridge:
```bash
node ws_proxy.js
```

### 3. Open `index.html` in a browser.

---

## 📜 Logging

All chat activity is written to:

```
chatlog.txt


---

## ✔️ Conclusion

This project implements a secure, stable, and fully functional chat room system using C and sockets.  
It satisfies all core project requirements and includes multiple optional enhancements such as password hashing, browser support, logging, and commands.

---

## 📚 Authors
Your Name(s), Group Number, Course, Semester
