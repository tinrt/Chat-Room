# Chat Room Application

A multi-threaded TCP chat room application written in C with client-server architecture.

## Features

- **User Authentication**: Register new users or login with existing credentials
- **Multi-threaded Server**: Handles multiple clients simultaneously using pthreads
- **Real-time Messaging**: Broadcast messages to all connected users
- **Secure Password Input**: Password input is hidden during authentication
- **Persistent User Storage**: User credentials are stored in `users.txt` with hashed passwords
- **User Status Tracking**: Prevents duplicate logins and tracks online users

## Files

- `p1g6S.c` - Server source code
- `p1g6C.c` - Client source code
- `users.txt` - Stores registered user credentials (username and hashed password)

## Compilation

```bash
# Compile the server
gcc -pthread -o server p1g6S.c

# Compile the client
gcc -pthread -o client p1g6C.c
```

## Usage

### Starting the Server

```bash
./server <port>
```

Example:
```bash
./server 1111
```

### Starting the Client

```bash
./client <server_address> <port>
```

Examples:
```bash
# Connect to local server
./client 127.0.0.1 1111

# Connect to remote server
./client csa.ramapo.edu 1111
```

## How to Use

1. **Start the server** on a specific port
2. **Launch one or more clients** to connect to the server
3. **Choose authentication option**:
   - Enter `1` to login with existing credentials
   - Enter `2` to register a new account
4. **Enter username and password**
5. Once authenticated, you can:
   - Type messages to chat with other users
   - Type `/quit` or `/exit` to disconnect

## Commands

- `/quit` - Exit the chat room
- `/exit` - Exit the chat room

## Technical Details

- **Protocol**: TCP/IP
- **Concurrency**: Multi-threaded using POSIX threads (pthreads)
- **Password Security**: Passwords are hashed using a simple hash function before storage
- **Maximum Clients**: 10 simultaneous connections (configurable)
- **Buffer Size**: 2048 bytes

## Requirements

- GCC compiler with pthread support
- POSIX-compliant system (Linux, macOS, Unix)
- C standard library

## Notes

- Usernames must be unique
- Users cannot login twice with the same account simultaneously
- Server prints status messages for user connections and disconnections
- Client connection is terminated on Ctrl+C or using exit commands
