/*
 * Cross-platform chat client
 * Features:
 *  - Connects to server on 127.0.0.1:9090
 *  - Handles registration/login dialogue
 *  - Hides password input (no echo)
 *  - Separate thread for receiving server messages
 *  - Type "/list" to see online users
 *  - Type "exit" to quit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h> /* _beginthreadex */
    #include <conio.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <pthread.h>
    #include <termios.h>
    #include <errno.h>
#endif

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 9090
#define BUFFER_SIZE 2048

#ifdef _WIN32
typedef SOCKET socket_t;
#define CLOSE_SOCKET(s) closesocket(s)
#else
typedef int socket_t;
#define CLOSE_SOCKET(s) close(s)
#endif

volatile int running = 1; // Global flag controlling main loop and receiver thread

/* =========================
   Hidden password input
   ========================= */

#ifdef _WIN32
// Windows: use _getch() to read characters without echo
void get_hidden_input(char *buf, size_t buflen) {
    size_t i = 0;
    int c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == '\b') { // Handle backspace
            if (i > 0) {
                i--;
            }
            continue;
        }
        if (i + 1 < buflen) {
            buf[i++] = (char)c;
        }
    }
    buf[i] = '\0';
}
#else
// POSIX: disable ECHO with termios for hidden input
void get_hidden_input(char *buf, size_t buflen) {
    struct termios old, newt;
    tcgetattr(STDIN_FILENO, &old);
    newt = old;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(buf, (int)buflen, stdin) == NULL) {
        buf[0] = '\0';
    } else {
        size_t len = strlen(buf);
        if (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
            buf[len - 1] = '\0';
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
}
#endif

/* =========================
   Receiver thread
   ========================= */

// Thread function to receive messages from server
void *recv_thread(void *arg) {
    socket_t sock = *(socket_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes;

    while (running) {
        bytes = (int)recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            printf("\n[System] Disconnected from server.\n");
            running = 0;
            break;
        }
        buffer[bytes] = '\0';
        // Print server messages on their own line
        printf("\n%s\n> ", buffer);
        fflush(stdout);
    }

    return NULL;
}

#ifdef _WIN32
// Windows thread wrapper for receiver thread
unsigned __stdcall win_recv_thread(void *arg) {
    recv_thread(arg);
    return 0;
}
#endif

/* =========================
   Authentication dialogue
   ========================= */

/*
 * Perform registration/login dialogue with server.
 * Returns 1 on success, 0 on failure.
 *
 * Strategy:
 *  - Read server prompts.
 *  - Whenever we see "password" in the prompt, we use hidden input.
 *  - Otherwise we use normal fgets().
 *  - Stop when we see "Login successful" or "Registration successful"
 *    or an error message.
 */
int perform_authentication(socket_t sock) {
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = (int)recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[n] = '\0';
        printf("%s", buffer);

        // Check for success/failure messages in what we just printed
        if (strstr(buffer, "Login successful") ||
            strstr(buffer, "Registration successful")) {
            // Auth done
            return 1;
        }
        if (strstr(buffer, "Invalid credentials") ||
            strstr(buffer, "Authentication failed") ||
            strstr(buffer, "Username already exists") ||
            strstr(buffer, "Server error")) {
            // Auth failed
            return 0;
        }

        // If server expects input after this prompt...
        if (strstr(buffer, "Do you have an account?") ||
            strstr(buffer, "Choose a username") ||
            strstr(buffer, "Username:") ||
            strstr(buffer, "Choose a password") ||
            strstr(buffer, "Password:")) {

            char input[256];

            if (strstr(buffer, "password") || strstr(buffer, "Password")) {
                // Hidden password input
                printf("(input hidden) ");
                fflush(stdout);
                get_hidden_input(input, sizeof(input));
                printf("\n");
            } else {
                if (!fgets(input, sizeof(input), stdin)) {
                    return 0;
                }
            }

            // Send input to server
            send(sock, input, (int)strlen(input), 0);
        }
    }

    return 0; // connection closed or error
}

/* =========================
   main()
   ========================= */
/* =========================
   Main loop and connection close FIXED
   ========================= */

int main(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize Winsock.\n");
        return 1;
    }
#endif

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
#else
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
#endif

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        printf("Invalid address.\n");
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
#ifdef _WIN32
        printf("Connection failed: %d\n", WSAGetLastError());
#else
        perror("Connection failed");
#endif
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("Authenticate to join the chat.\n\n");

    if (!perform_authentication(sock)) {
        printf("Authentication failed. Exiting.\n");
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("\n[System] You are now in the chat.\n");
    printf("Type messages below. Type 'exit' to quit. Type '/list' to see online users.\n");

    /* =========================
       Start receiver thread
       ========================= */
#ifdef _WIN32
    uintptr_t th = _beginthreadex(NULL, 0, win_recv_thread, &sock, 0, NULL);
    if (th == 0) {
        printf("Failed to create receive thread.\n");
        CLOSE_SOCKET(sock);
        WSACleanup();
        return 1;
    }
#else
    pthread_t th;
    if (pthread_create(&th, NULL, recv_thread, &sock) != 0) {
        perror("pthread_create");
        CLOSE_SOCKET(sock);
        return 1;
    }
#endif

    /* =========================
       Main input loop (FIXED)
       ========================= */

    char message[BUFFER_SIZE];
    while (running) {
        printf("> ");
        fflush(stdout);

        if (!fgets(message, sizeof(message), stdin))
            break;

        // If user types "exit", close immediately
        if (strncmp(message, "exit", 4) == 0) {

            // 1. Tell server we're exiting
            send(sock, "exit\n", 5, 0);

            // 2. Stop receiver thread
            running = 0;

#ifdef _WIN32
            shutdown(sock, SD_BOTH);
#else
            shutdown(sock, SHUT_RDWR);
#endif

            break;
        }

        // Normal message → send
        send(sock, message, (int)strlen(message), 0);
    }

    printf("Closing connection...\n");

    /* =========================
       Wait for receiver thread to end
       ========================= */

#ifdef _WIN32
    WaitForSingleObject((HANDLE)th, INFINITE);
    CloseHandle((HANDLE)th);
#else
    pthread_join(th, NULL);
#endif

    CLOSE_SOCKET(sock);

#ifdef _WIN32
    WSACleanup();
#endif

    printf("Disconnected.\n");
    return 0;
}
