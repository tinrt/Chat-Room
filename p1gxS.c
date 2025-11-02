#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define PORT 9090
#define MAX_CLIENTS 10
#define BUFFER_SIZE 2048

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

static socket_t clients[MAX_CLIENTS];

#ifdef _WIN32
    static CRITICAL_SECTION clients_mutex;
    #define mutex_init() InitializeCriticalSection(&clients_mutex)
    #define mutex_lock() EnterCriticalSection(&clients_mutex)
    #define mutex_unlock() LeaveCriticalSection(&clients_mutex)
    #define mutex_destroy() DeleteCriticalSection(&clients_mutex)
#else
    static pthread_mutex_t clients_mutex;
    #define mutex_init() pthread_mutex_init(&clients_mutex, NULL)
    #define mutex_lock() pthread_mutex_lock(&clients_mutex)
    #define mutex_unlock() pthread_mutex_unlock(&clients_mutex)
    #define mutex_destroy() pthread_mutex_destroy(&clients_mutex)
#endif

void broadcast_message(const char *message, size_t length, socket_t sender_fd) {
    mutex_lock();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        socket_t fd = clients[i];
        if (fd != INVALID_SOCKET_VALUE && fd != sender_fd) {
            int sent = (int)send(fd, message, (int)length, 0);
            (void)sent;
        }
    }
    mutex_unlock();
}

void *handle_client(void *arg) {
    socket_t client_fd = *(socket_t *)arg;
    free(arg);

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = (int)recv(client_fd, buffer, (int)sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Received from %ld: %s\n", (long)client_fd, buffer);
        broadcast_message(buffer, (size_t)bytes_read, client_fd);
    }

    if (bytes_read == 0) {
        printf("Client %ld disconnected\n", (long)client_fd);
    } else {
#ifdef _WIN32
        fprintf(stderr, "recv failed for %ld: %d\n", (long)client_fd, WSAGetLastError());
#else
        fprintf(stderr, "recv failed for %ld: %s\n", (long)client_fd, strerror(errno));
#endif
    }

    CLOSE_SOCKET(client_fd);

    mutex_lock();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == client_fd) {
            clients[i] = INVALID_SOCKET_VALUE;
            break;
        }
    }
    mutex_unlock();

    return NULL;
}

#ifdef _WIN32
DWORD WINAPI win_handle_client(LPVOID arg) {
    handle_client(arg);
    return 0;
}
#endif

int main(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    for (int i = 0; i < MAX_CLIENTS; i++) clients[i] = INVALID_SOCKET_VALUE;

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

    int opt = 1;
#ifdef _WIN32
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) != 0) {
        fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
    }
#else
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        perror("setsockopt failed");
    }
#endif

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
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

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        socket_t client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

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

        char addrstr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, addrstr, sizeof(addrstr));
        printf("Connection from %s:%d (fd=%ld)\n", addrstr, ntohs(client_addr.sin_port), (long)client_fd);

        int added = 0;
        mutex_lock();
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == INVALID_SOCKET_VALUE) {
                clients[i] = client_fd;
                added = 1;
                break;
            }
        }
        mutex_unlock();

        if (!added) {
            fprintf(stderr, "Max clients reached, rejecting connection %ld\n", (long)client_fd);
            CLOSE_SOCKET(client_fd);
            continue;
        }

        socket_t *pclient = malloc(sizeof(socket_t));
        if (!pclient) {
            perror("malloc");
            CLOSE_SOCKET(client_fd);
            mutex_lock();
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = INVALID_SOCKET_VALUE;
                    break;
                }
            }
            mutex_unlock();
            continue;
        }
        *pclient = client_fd;

#ifdef _WIN32
        uintptr_t th = _beginthreadex(NULL, 0, (unsigned (__stdcall *)(void *))win_handle_client, pclient, 0, NULL);
        if (th == 0) {
            fprintf(stderr, "_beginthreadex failed\n");
            CLOSE_SOCKET(client_fd);
            free(pclient);
            mutex_lock();
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = INVALID_SOCKET_VALUE;
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
                    break;
                }
            }
            mutex_unlock();
            continue;
        }
        pthread_detach(ptid);
#endif

        printf("New client accepted (fd=%ld)\n", (long)client_fd);
    }

    CLOSE_SOCKET(server_fd);
    mutex_destroy();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
