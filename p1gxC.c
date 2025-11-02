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

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090
#define BUFFER_SIZE 2048

#ifdef _WIN32
typedef SOCKET socket_t;
#define CLOSE_SOCKET(s) closesocket(s)
#else
typedef int socket_t;
#define CLOSE_SOCKET(s) close(s)
#endif

volatile int running = 1;

void *recv_thread(void *arg) {
    socket_t sock = *(socket_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes;

    while (running) {
        bytes = (int)recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            printf("Disconnected from server.\n");
            running = 0;
            break;
        }
        buffer[bytes] = '\0';
        printf("\n[Server] %s\n> ", buffer);
        fflush(stdout);
    }

    return NULL;
}

#ifdef _WIN32
unsigned __stdcall win_recv_thread(void *arg) {
    recv_thread(arg);
    return 0;
}
#endif

int main(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize Winsock.\n");
        return 1;
    }
#endif

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#ifdef _WIN32
        printf("Socket creation failed: %d\n", WSAGetLastError());
#else
        perror("Socket creation failed");
#endif
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        printf("Invalid address/Address not supported.\n");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
#ifdef _WIN32
        printf("Connection failed: %d\n", WSAGetLastError());
#else
        perror("Connection failed");
#endif
        CLOSE_SOCKET(sock);
        return 1;
    }

    printf("Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("Type messages below. Type 'exit' to quit.\n");

#ifdef _WIN32
    uintptr_t th = _beginthreadex(NULL, 0, win_recv_thread, &sock, 0, NULL);
#else
    pthread_t th;
    pthread_create(&th, NULL, recv_thread, &sock);
#endif

    char message[BUFFER_SIZE];
    while (running) {
        printf("> ");
        fflush(stdout);
        if (!fgets(message, sizeof(message), stdin))
            break;

        if (strncmp(message, "exit", 4) == 0)
            break;

        send(sock, message, (int)strlen(message), 0);
    }

    running = 0;
    printf("Closing connection...\n");

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
