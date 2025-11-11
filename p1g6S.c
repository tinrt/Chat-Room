#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 2048
#define USERNAME_SIZE 32
#define PASSWORD_SIZE 64
#define USER_FILE "users.txt"

// Client structure to store client information
typedef struct {
    int sockfd;
    char username[USERNAME_SIZE];
    struct sockaddr_in address;
    int active;
} client_t;

// User credentials structure
typedef struct {
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
} user_credentials_t;

// Global variables
client_t *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
int client_count = 0;

// Function prototypes
void *handle_client(void *arg);
void broadcast_message(char *message, int sender_fd);
void add_client(client_t *client);
void remove_client(int sockfd);
void print_client_addr(struct sockaddr_in addr);
int is_username_taken(const char *username);
int is_user_online(const char *username);
int authenticate_user(const char *username, const char *password);
int register_user(const char *username, const char *password);
void init_user_file();
unsigned long hash_password(const char *password);
int recv_line(int sockfd, char *buffer, int max_len);

// Initialize user file if it doesn't exist
void init_user_file() {
    FILE *file = fopen(USER_FILE, "a");
    if (file) {
        fclose(file);
    }
}

// Simple hash function for passwords (for basic security)
unsigned long hash_password(const char *password) {
    unsigned long hash = 5381;
    int c;
    while ((c = *password++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Check if username is already taken (registered in file)
int is_username_taken(const char *username) {
    // Check registered users in file
    pthread_mutex_lock(&file_mutex);
    FILE *file = fopen(USER_FILE, "r");
    if (file) {
        char stored_username[USERNAME_SIZE];
        unsigned long stored_hash;
        
        while (fscanf(file, "%s %lu", stored_username, &stored_hash) == 2) {
            if (strcmp(stored_username, username) == 0) {
                fclose(file);
                pthread_mutex_unlock(&file_mutex);
                return 1;
            }
        }
        fclose(file);
    }
    pthread_mutex_unlock(&file_mutex);
    
    return 0;
}

// Check if user is currently online
int is_user_online(const char *username) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->active && 
            strcmp(clients[i]->username, username) == 0) {
            pthread_mutex_unlock(&clients_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return 0;
}

// Authenticate user with username and password
int authenticate_user(const char *username, const char *password) {
    pthread_mutex_lock(&file_mutex);
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        pthread_mutex_unlock(&file_mutex);
        return 0;
    }
    
    char stored_username[USERNAME_SIZE];
    unsigned long stored_hash;
    unsigned long input_hash = hash_password(password);
    
    while (fscanf(file, "%s %lu", stored_username, &stored_hash) == 2) {
        if (strcmp(stored_username, username) == 0) {
            fclose(file);
            pthread_mutex_unlock(&file_mutex);
            return (stored_hash == input_hash);
        }
    }
    
    fclose(file);
    pthread_mutex_unlock(&file_mutex);
    return 0;
}

// Register a new user
int register_user(const char *username, const char *password) {
    pthread_mutex_lock(&file_mutex);
    FILE *file = fopen(USER_FILE, "a");
    if (!file) {
        pthread_mutex_unlock(&file_mutex);
        return 0;
    }
    
    unsigned long password_hash = hash_password(password);
    fprintf(file, "%s %lu\n", username, password_hash);
    fclose(file);
    pthread_mutex_unlock(&file_mutex);
    
    return 1;
}

// Add a client to the clients array
void add_client(client_t *client) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            clients[i] = client;
            client_count++;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Remove a client from the clients array
void remove_client(int sockfd) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->sockfd == sockfd) {
            clients[i]->active = 0;
            free(clients[i]);
            clients[i] = NULL;
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Broadcast message to all clients except sender
void broadcast_message(char *message, int sender_fd) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->active && clients[i]->sockfd != sender_fd) {
            if (send(clients[i]->sockfd, message, strlen(message), 0) < 0) {
                perror("Send failed");
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Print client IP address
void print_client_addr(struct sockaddr_in addr) {
    printf("%s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

// Receive a line (until newline) from socket
int recv_line(int sockfd, char *buffer, int max_len) {
    int i = 0;
    char c;
    
    while (i < max_len - 1) {
        int n = recv(sockfd, &c, 1, 0);
        if (n <= 0) {
            return -1;
        }
        if (c == '\n') {
            break;
        }
        buffer[i++] = c;
    }
    buffer[i] = '\0';
    return i;
}

// Handle authentication for a client
int handle_authentication(client_t *client) {
    char buffer[BUFFER_SIZE];
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
    char auth_type[10];
    
    // Receive authentication type (LOGIN or REGISTER)
    if (recv_line(client->sockfd, auth_type, sizeof(auth_type)) < 0) {
        return 0;
    }
    
    // Receive username
    if (recv_line(client->sockfd, username, USERNAME_SIZE) < 0) {
        return 0;
    }
    
    // Receive password
    if (recv_line(client->sockfd, password, PASSWORD_SIZE) < 0) {
        return 0;
    }
    
    // Handle registration
    if (strcmp(auth_type, "REGISTER") == 0) {
        if (is_username_taken(username)) {
            send(client->sockfd, "FAIL:Username already exists", 30, 0);
            return 0;
        }
        
        if (register_user(username, password)) {
            strcpy(client->username, username);
            send(client->sockfd, "SUCCESS", 7, 0);
            printf(">>> New user registered: %s\n", username);
            return 1;
        } else {
            send(client->sockfd, "FAIL:Registration failed", 25, 0);
            return 0;
        }
    }
    // Handle login
    else if (strcmp(auth_type, "LOGIN") == 0) {
        if (!authenticate_user(username, password)) {
            send(client->sockfd, "FAIL:Invalid username or password", 35, 0);
            return 0;
        }
        
        if (is_user_online(username)) {
            send(client->sockfd, "FAIL:User already logged in", 28, 0);
            return 0;
        }
        
        strcpy(client->username, username);
        send(client->sockfd, "SUCCESS", 7, 0);
        return 1;
    }
    
    return 0;
}

// Handle communication with a client
void *handle_client(void *arg) {
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE + USERNAME_SIZE + 10];
    int leave_flag = 0;
    
    client_t *client = (client_t *)arg;
    
    // Handle authentication
    if (!handle_authentication(client)) {
        printf("Authentication failed for client from ");
        print_client_addr(client->address);
        printf("\n");
        close(client->sockfd);
        remove_client(client->sockfd);
        pthread_detach(pthread_self());
        return NULL;
    }
    
    // Print connection info
    printf(">>> %s has joined the chat from ", client->username);
    print_client_addr(client->address);
    printf("\n");
    
    // Notify all clients
    sprintf(message, ">>> %s has joined the chat!\n", client->username);
    broadcast_message(message, client->sockfd);
    
    // Main message handling loop
    while (!leave_flag) {
        int receive = recv(client->sockfd, buffer, BUFFER_SIZE, 0);
        
        if (receive > 0) {
            buffer[receive] = '\0';
            buffer[strcspn(buffer, "\n")] = '\0';
            
            // Check for empty message
            if (strlen(buffer) == 0) {
                continue;
            }
            
            // Format and broadcast message
            sprintf(message, "[%s]: %s\n", client->username, buffer);
            printf("%s", message);
            broadcast_message(message, client->sockfd);
            
        } else if (receive == 0) {
            // Client disconnected
            printf("<<< %s has left the chat\n", client->username);
            sprintf(message, "<<< %s has left the chat\n", client->username);
            broadcast_message(message, client->sockfd);
            leave_flag = 1;
        } else {
            perror("Receive error");
            leave_flag = 1;
        }
    }
    
    // Cleanup
    close(client->sockfd);
    remove_client(client->sockfd);
    pthread_detach(pthread_self());
    
    return NULL;
}

int main(int argc, char *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t tid;
    
    // Check command line arguments
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    int PORT = atoi(argv[1]);
    
    // Initialize user file
    init_user_file();
    
    // Initialize clients array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = NULL;
    }
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("=== Chat Room Server ===\n");
    printf("Listening on port %d...\n", PORT);
    printf("User database: %s\n", USER_FILE);
    printf("Waiting for clients...\n\n");
    
    // Main server loop - accept clients
    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Check if max clients reached
        if (client_count >= MAX_CLIENTS) {
            printf("Max clients reached. Connection rejected.\n");
            close(new_socket);
            continue;
        }
        
        // Create new client structure
        client_t *client = (client_t *)malloc(sizeof(client_t));
        client->sockfd = new_socket;
        client->address = client_addr;
        client->active = 1;
        
        // Add client and create thread
        add_client(client);
        
        if (pthread_create(&tid, NULL, handle_client, (void *)client) != 0) {
            perror("Thread creation failed");
            remove_client(new_socket);
            free(client);
        }
    }
    
    close(server_fd);
    return 0;
}