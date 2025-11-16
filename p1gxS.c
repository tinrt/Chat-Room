/*
 * Cross-platform multi-client chat server
 * Features:
 *  - Registration & login with username
 *  - Passwords stored as SHA-256 hashes in users.db
 *  - Join/leave announcements
 *  - /list command: show online users
 *  - Simple message logging in chatlog.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h> /* _beginthreadex */
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <pthread.h>
    #include <errno.h>
#endif

#define PORT         9090           // Server port
#define MAX_CLIENTS  10             // Maximum number of clients
#define BUFFER_SIZE  2048           // Buffer size for messages

#ifdef _WIN32
    typedef SOCKET socket_t;
    typedef int socklen_t;
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
#else
    typedef int socket_t;
    #define INVALID_SOCKET_VALUE (-1)
    #define CLOSE_SOCKET(s) close(s)
#endif

/* =========================
   Global client structures
   ========================= */

// Array to store client sockets
static socket_t clients[MAX_CLIENTS];
// Array to store usernames for each client
static char     clients_usernames[MAX_CLIENTS][64];

#ifdef _WIN32
    static CRITICAL_SECTION clients_mutex;
    #define mutex_init()    InitializeCriticalSection(&clients_mutex)
    #define mutex_lock()    EnterCriticalSection(&clients_mutex)
    #define mutex_unlock()  LeaveCriticalSection(&clients_mutex)
    #define mutex_destroy() DeleteCriticalSection(&clients_mutex)
#else
    static pthread_mutex_t clients_mutex;
    #define mutex_init()    pthread_mutex_init(&clients_mutex, NULL)
    #define mutex_lock()    pthread_mutex_lock(&clients_mutex)
    #define mutex_unlock()  pthread_mutex_unlock(&clients_mutex)
    #define mutex_destroy() pthread_mutex_destroy(&clients_mutex)
#endif

/* =========================
   SHA-256 implementation
   (for hashing passwords)
   ========================= */

#define SHA256_BLOCK_SIZE 32  // 256 bits

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx;

// SHA-256 constants
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
static uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
static uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
static uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
static uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA-256 transformation function
static void sha256_transform(sha256_ctx *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t m[64];
    int i, j;

    // Prepare message schedule
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) |
               (data[j + 1] << 16) |
               (data[j + 2] << 8) |
               (data[j + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    // Initialize working variables
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // Main compression loop
    for (i = 0; i < 64; ++i) {
        t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
        t2 = ep0(a) + maj(a, b, c);
        h  = g;
        g  = f;
        f  = e;
        e  = d + t1;
        d  = c;
        c  = b;
        b  = a;
        a  = t1 + t2;
    }

    // Add compressed chunk to current hash value
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// Initialize SHA-256 context
static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen  = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// Update SHA-256 context with data
static void sha256_update(sha256_ctx *ctx, const uint8_t data[], size_t len) {
    size_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;  // 64 bytes * 8 bits
            ctx->datalen = 0;
        }
    }
}

// Finalize SHA-256 and produce hash
static void sha256_final(sha256_ctx *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    // Pad whatever data is left in the buffer
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    // Append total message length in bits and transform
    ctx->bitlen += ((uint64_t)ctx->datalen) * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen      );
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8 );
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    // Convert state to big-endian byte array
    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
    }
}

// Convenience: hash a string and return hex representation (64 chars + '\0')
static void sha256_string_hex(const char *input, char out_hex[65]) {
    uint8_t hash[SHA256_BLOCK_SIZE];
    sha256_ctx ctx;
    size_t len = strlen(input);
    static const char *hex_chars = "0123456789abcdef";

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)input, len);
    sha256_final(&ctx, hash);

    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        out_hex[i * 2]     = hex_chars[(hash[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[ hash[i]       & 0x0F];
    }
    out_hex[64] = '\0';
}

/* =========================
   Utility helpers
   ========================= */

// Remove trailing newline and carriage return from string
static void trim_newline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

/*
 * Broadcast message to all clients except sender_fd.
 * If sender_fd == -1, send to everyone.
 */
void broadcast_message(const char *message, size_t length, socket_t sender_fd) {
    mutex_lock();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        socket_t fd = clients[i];
        if (fd != INVALID_SOCKET_VALUE && (sender_fd == -1 || fd != sender_fd)) {
#ifdef _WIN32
            send(fd, message, (int)length, 0);
#else
            send(fd, message, length, 0);
#endif
        }
    }
    mutex_unlock();
}

/*
 * Send list of online users to a single client (used by /list command)
 */
void send_user_list(socket_t fd) {
    char buffer[BUFFER_SIZE];
    int offset = snprintf(buffer, sizeof(buffer), "Online users:\n");

    mutex_lock();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] != INVALID_SOCKET_VALUE && clients_usernames[i][0] != '\0') {
            int remaining = (int)sizeof(buffer) - offset;
            if (remaining <= 0) break;

            offset += snprintf(buffer + offset,
                               remaining,
                               " - %s\n", clients_usernames[i]);
        }
    }
    mutex_unlock();

#ifdef _WIN32
    send(fd, buffer, (int)strlen(buffer), 0);
#else
    send(fd, buffer, strlen(buffer), 0);
#endif
}

/* =========================
   Authentication
   ========================= */

/*
 * Very simple text file "users.db"
 * Each line: username:sha256hex
 */

// Authenticate client (registration or login)
int authenticate_client(socket_t fd, char *username_out, size_t username_out_len) {
    char buffer[256];

    // Ask if they have an account
    const char *q1 = "Do you have an account? (yes/no): ";
#ifdef _WIN32
    send(fd, q1, (int)strlen(q1), 0);
#else
    send(fd, q1, strlen(q1), 0);
#endif

    int n = (int)recv(fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) return 0;
    buffer[n] = '\0';
    trim_newline(buffer);

    int has_account = 1;
    if (buffer[0] == 'n' || buffer[0] == 'N') {
        has_account = 0;
    }

    if (!has_account) {
        // ===== Registration flow =====

        // Ask for username
        const char *ask_user = "Choose a username: ";
#ifdef _WIN32
        send(fd, ask_user, (int)strlen(ask_user), 0);
#else
        send(fd, ask_user, strlen(ask_user), 0);
#endif
        n = (int)recv(fd, username_out, (int)username_out_len - 1, 0);
        if (n <= 0) return 0;
        username_out[n] = '\0';
        trim_newline(username_out);

        // Check if username already exists
        FILE *fcheck = fopen("users.db", "r");
        if (fcheck) {
            char line[256];
            while (fgets(line, sizeof(line), fcheck)) {
                char u[64], h[130];
                if (sscanf(line, "%63[^:]:%129[^\n]", u, h) == 2) {
                    if (strcmp(u, username_out) == 0) {
                        const char *msg = "Username already exists. Please reconnect and choose another.\n";
#ifdef _WIN32
                        send(fd, msg, (int)strlen(msg), 0);
#else
                        send(fd, msg, strlen(msg), 0);
#endif
                        fclose(fcheck);
                        return 0;
                    }
                }
            }
            fclose(fcheck);
        }

        // Ask for password
        const char *ask_pass = "Choose a password: ";
#ifdef _WIN32
        send(fd, ask_pass, (int)strlen(ask_pass), 0);
#else
        send(fd, ask_pass, strlen(ask_pass), 0);
#endif
        n = (int)recv(fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) return 0;
        buffer[n] = '\0';
        trim_newline(buffer);

        // Hash password
        char hexhash[65];
        sha256_string_hex(buffer, hexhash);

        // Store username and hash in users.db
        FILE *f = fopen("users.db", "a");
        if (!f) {
            const char *msg = "Server error: cannot open users.db for writing.\n";
#ifdef _WIN32
            send(fd, msg, (int)strlen(msg), 0);
#else
            send(fd, msg, strlen(msg), 0);
#endif
            return 0;
        }
        fprintf(f, "%s:%s\n", username_out, hexhash);
        fclose(f);

        const char *ok = "Registration successful. You are now logged in.\n";
#ifdef _WIN32
        send(fd, ok, (int)strlen(ok), 0);
#else
        send(fd, ok, strlen(ok), 0);
#endif
        return 1;
    } else {
        // ===== Login flow =====

        // Ask for username
        const char *ask_user = "Username: ";
#ifdef _WIN32
        send(fd, ask_user, (int)strlen(ask_user), 0);
#else
        send(fd, ask_user, strlen(ask_user), 0);
#endif
        n = (int)recv(fd, username_out, (int)username_out_len - 1, 0);
        if (n <= 0) return 0;
        username_out[n] = '\0';
        trim_newline(username_out);

        // Ask for password
        const char *ask_pass = "Password: ";
#ifdef _WIN32
        send(fd, ask_pass, (int)strlen(ask_pass), 0);
#else
        send(fd, ask_pass, strlen(ask_pass), 0);
#endif
        n = (int)recv(fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) return 0;
        buffer[n] = '\0';
        trim_newline(buffer);

        // Hash password
        char input_hash[65];
        sha256_string_hex(buffer, input_hash);

        // Check credentials in users.db
        FILE *f = fopen("users.db", "r");
        if (!f) {
            const char *msg = "No user database found. Please register first.\n";
#ifdef _WIN32
            send(fd, msg, (int)strlen(msg), 0);
#else
            send(fd, msg, strlen(msg), 0);
#endif
            return 0;
        }

        int found = 0;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char u[64], h[130];
            if (sscanf(line, "%63[^:]:%129[^\n]", u, h) == 2) {
                if (strcmp(u, username_out) == 0 && strcmp(h, input_hash) == 0) {
                    found = 1;
                    break;
                }
            }
        }
        fclose(f);

        if (!found) {
            const char *bad = "Invalid credentials.\n";
#ifdef _WIN32
            send(fd, bad, (int)strlen(bad), 0);
#else
            send(fd, bad, strlen(bad), 0);
#endif
            return 0;
        }

        const char *ok = "Login successful.\n";
#ifdef _WIN32
        send(fd, ok, (int)strlen(ok), 0);
#else
        send(fd, ok, strlen(ok), 0);
#endif
        return 1;
    }
}

/* =========================
   Client handler
   ========================= */

/*
 * Thread function to handle a single client.
 * Handles authentication, message receiving, broadcasting, and cleanup.
 */
void *handle_client(void *arg) {
    socket_t client_fd = *(socket_t *)arg;
    free(arg);

    char username[64] = {0};

    // Authenticate client
    if (!authenticate_client(client_fd, username, sizeof(username))) {
        const char *msg = "Authentication failed. Closing connection.\n";
#ifdef _WIN32
        send(client_fd, msg, (int)strlen(msg), 0);
#else
        send(client_fd, msg, strlen(msg), 0);
#endif
        CLOSE_SOCKET(client_fd);

        // Remove from client list if already inserted
        mutex_lock();
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == client_fd) {
                clients[i] = INVALID_SOCKET_VALUE;
                clients_usernames[i][0] = '\0';
                break;
            }
        }
        mutex_unlock();
        return NULL;
    }

    // Store username in global array
    int index = -1;
    mutex_lock();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == client_fd) {
            index = i;
            break;
        }
    }
    if (index >= 0) {
        strncpy(clients_usernames[index], username, sizeof(clients_usernames[index]) - 1);
        clients_usernames[index][sizeof(clients_usernames[index]) - 1] = '\0';
    }
    mutex_unlock();

    // Announce join to everyone
    char notif[256];
    snprintf(notif, sizeof(notif), "🟢 %s joined the chat.\n", username);
    broadcast_message(notif, strlen(notif), -1);
    printf("%s", notif);

    // Log join
    {
        FILE *logf = fopen("chatlog.txt", "a");
        if (logf) {
            fprintf(logf, "%s joined.\n", username);
            fclose(logf);
        }
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    // Main loop: receive messages from client
    while ((bytes_read = (int)recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        trim_newline(buffer);

        if (buffer[0] == '\0') {
            continue; // ignore empty lines
        }

        // Handle /list command locally (do not broadcast)
        if (strncmp(buffer, "/list", 5) == 0) {
            send_user_list(client_fd);
            continue;
        }

        // Prefix message with username
        char msg[BUFFER_SIZE + 128];
        snprintf(msg, sizeof(msg), "%s: %s\n", username, buffer);
        printf("%s", msg);

        // Log to file
        FILE *logf = fopen("chatlog.txt", "a");
        if (logf) {
            fprintf(logf, "%s", msg);
            fclose(logf);
        }

        // Broadcast to others
        broadcast_message(msg, strlen(msg), client_fd);
    }

    // Connection closed or error
    if (bytes_read == 0) {
        printf("Client %s disconnected.\n", username);
    } else {
#ifdef _WIN32
        fprintf(stderr, "recv failed for %s: %d\n", username, WSAGetLastError());
#else
        fprintf(stderr, "recv failed for %s: %s\n", username, strerror(errno));
#endif
    }

    // Announce leave
    snprintf(notif, sizeof(notif), "🔴 %s left the chat.\n", username);
    broadcast_message(notif, strlen(notif), -1);
    printf("%s", notif);

    // Log leave
    {
        FILE *logf = fopen("chatlog.txt", "a");
        if (logf) {
            fprintf(logf, "%s left.\n", username);
            fclose(logf);
        }
    }

    // Remove client from list
    mutex_lock();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == client_fd) {
            clients[i] = INVALID_SOCKET_VALUE;
            clients_usernames[i][0] = '\0';
            break;
        }
    }
    mutex_unlock();

    CLOSE_SOCKET(client_fd);
    return NULL;
}

#ifdef _WIN32
// Windows thread wrapper for handle_client
DWORD WINAPI win_handle_client(LPVOID arg) {
    handle_client(arg);
    return 0;
}
#endif

/* =========================
   main()
   ========================= */

/*
 * Main server loop.
 * Accepts new connections, creates threads for clients,
 * and manages client list.
 */
int main(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    // Initialize client arrays
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = INVALID_SOCKET_VALUE;
        clients_usernames[i][0] = '\0';
    }

    // Create server socket
    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (server_fd == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
#else
    if (server_fd == -1) {
        perror("Socket creation failed");
        return 1;
    }
#endif

    // Set socket options
    int opt = 1;
#ifdef _WIN32
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                   (const char *)&opt, sizeof(opt)) != 0) {
        fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
    }
#else
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)) != 0) {
        perror("setsockopt failed");
    }
#endif

    // Bind server socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
#ifdef _WIN32
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        CLOSE_SOCKET(server_fd);
        WSACleanup();
#else
        perror("Bind failed");
        CLOSE_SOCKET(server_fd);
#endif
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 5) < 0) {
#ifdef _WIN32
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        CLOSE_SOCKET(server_fd);
        WSACleanup();
#else
        perror("Listen failed");
        CLOSE_SOCKET(server_fd);
#endif
        return 1;
    }

    printf("Server started on port %d...\n", PORT);

    mutex_init();

    // Main accept loop
    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        socket_t client_fd = accept(server_fd,
                                    (struct sockaddr *)&client_addr,
                                    &client_len);
#ifdef _WIN32
        if (client_fd == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
            continue;
        }
#else
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }
#endif

        // Store client in clients[] or reject if full
        int added = 0;
        mutex_lock();
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == INVALID_SOCKET_VALUE) {
                clients[i] = client_fd;
                clients_usernames[i][0] = '\0'; // will be filled after auth
                added = 1;
                break;
            }
        }
        mutex_unlock();

        if (!added) {
            const char *msg = "Server is full. Try again later.\n";
#ifdef _WIN32
            send(client_fd, msg, (int)strlen(msg), 0);
#else
            send(client_fd, msg, strlen(msg), 0);
#endif
            CLOSE_SOCKET(client_fd);
            continue;
        }

        // Print connection info
        char addrstr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, addrstr, sizeof(addrstr));
        printf("New connection from %s:%d (fd=%ld)\n",
               addrstr, ntohs(client_addr.sin_port), (long)client_fd);

        // Create thread for client
        socket_t *pclient = (socket_t *)malloc(sizeof(socket_t));
        if (!pclient) {
            perror("malloc");
            CLOSE_SOCKET(client_fd);
            mutex_lock();
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = INVALID_SOCKET_VALUE;
                    clients_usernames[i][0] = '\0';
                    break;
                }
            }
            mutex_unlock();
            continue;
        }
        *pclient = client_fd;

#ifdef _WIN32
        uintptr_t th = _beginthreadex(NULL, 0,
                                      (unsigned (__stdcall *)(void *))win_handle_client,
                                      pclient, 0, NULL);
        if (th == 0) {
            fprintf(stderr, "_beginthreadex failed\n");
            CLOSE_SOCKET(client_fd);
            free(pclient);
            mutex_lock();
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = INVALID_SOCKET_VALUE;
                    clients_usernames[i][0] = '\0';
                    break;
                }
            }
            mutex_unlock();
            continue;
        }
        CloseHandle((HANDLE)th);
#else
        pthread_t ptid;
        if (pthread_create(&ptid, NULL, handle_client, pclient) != 0) {
            perror("pthread_create");
            CLOSE_SOCKET(client_fd);
            free(pclient);
            mutex_lock();
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = INVALID_SOCKET_VALUE;
                    clients_usernames[i][0] = '\0';
                    break;
                }
            }
            mutex_unlock();
            continue;
        }
        pthread_detach(ptid);
#endif
    }

    // Cleanup (unreached)
    CLOSE_SOCKET(server_fd);
    mutex_destroy();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
