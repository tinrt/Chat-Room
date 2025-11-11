#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>

#define BUFFER_SIZE 2048
#define USERNAME_SIZE 32
#define PASSWORD_SIZE 64

// Global variables
int sockfd;
char username[USERNAME_SIZE];
volatile int running = 1;

// Function prototypes
void *receive_messages(void *arg);
void send_message();
void str_trim_lf(char *arr, int length);
int authenticate_with_server();
void get_password(char *password, int max_len);

// Remove newline character from string
void str_trim_lf(char *arr, int length) {
    for (int i = 0; i < length; i++) {
        if (arr[i] == '\n') {
            arr[i] = '\0';
            break;
        }
    }
}

// Get password input without echoing to terminal
void get_password(char *password, int max_len) {
    struct termios old_term, new_term;
    int i = 0;
    int c;
    
    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    
    // Disable echo
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    // Read password
    while (i < max_len - 1 && (c = getchar()) != '\n' && c != EOF) {
        password[i++] = c;
    }
    password[i] = '\0';
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");
}

// Authenticate with server (login or register)
int authenticate_with_server() {
    char choice[10];
    char password[PASSWORD_SIZE];
    char response[BUFFER_SIZE];
    
    printf("\n=== Authentication ===\n");
    printf("1. Login\n");
    printf("2. Register\n");
    printf("Choose (1 or 2): ");
    fgets(choice, sizeof(choice), stdin);
    str_trim_lf(choice, sizeof(choice));
    
    // Get username
    printf("Username: ");
    fgets(username, USERNAME_SIZE, stdin);
    str_trim_lf(username, USERNAME_SIZE);
    
    // Validate username
    if (strlen(username) == 0 || strlen(username) >= USERNAME_SIZE - 1) {
        printf("Invalid username. Must be 1-%d characters.\n", USERNAME_SIZE - 2);
        return 0;
    }
    
    // Get password
    printf("Password: ");
    get_password(password, PASSWORD_SIZE);
    
    // Validate password
    if (strlen(password) == 0) {
        printf("Password cannot be empty.\n");
        return 0;
    }
    
    // Send authentication type with newline
    if (strcmp(choice, "1") == 0) {
        send(sockfd, "LOGIN\n", 6, 0);
    } else if (strcmp(choice, "2") == 0) {
        send(sockfd, "REGISTER\n", 9, 0);
    } else {
        printf("Invalid choice.\n");
        return 0;
    }
    
    // Small delay to ensure messages don't combine
    usleep(10000);
    
    // Send username with newline
    char user_msg[USERNAME_SIZE + 2];
    snprintf(user_msg, sizeof(user_msg), "%s\n", username);
    send(sockfd, user_msg, strlen(user_msg), 0);
    
    // Small delay
    usleep(10000);
    
    // Send password with newline
    char pass_msg[PASSWORD_SIZE + 2];
    snprintf(pass_msg, sizeof(pass_msg), "%s\n", password);
    send(sockfd, pass_msg, strlen(pass_msg), 0);
    
    // Clear password from memory
    memset(password, 0, sizeof(password));
    
    // Receive authentication response
    int valread = recv(sockfd, response, BUFFER_SIZE - 1, 0);
    if (valread <= 0) {
        printf("Connection lost during authentication.\n");
        return 0;
    }
    
    response[valread] = '\0';
    
    if (strcmp(response, "SUCCESS") == 0) {
        if (strcmp(choice, "1") == 0) {
            printf("\n✓ Login successful! Welcome back, %s!\n", username);
        } else {
            printf("\n✓ Registration successful! Welcome, %s!\n", username);
        }
        return 1;
    } else {
        // Parse error message
        if (strncmp(response, "FAIL:", 5) == 0) {
            printf("\n✗ Authentication failed: %s\n", response + 5);
        } else {
            printf("\n✗ Authentication failed.\n");
        }
        return 0;
    }
}

// Thread function to receive messages from server
void *receive_messages(void *arg) {
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int receive = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
        
        if (receive > 0) {
            buffer[receive] = '\0';
            printf("%s", buffer);
            fflush(stdout);
        } else if (receive == 0) {
            printf("\n<<< Server disconnected >>>\n");
            running = 0;
            break;
        } else {
            // Error occurred
            break;
        }
    }
    
    return NULL;
}

// Function to send messages to server
void send_message() {
    char message[BUFFER_SIZE];
    
    while (running) {
        fgets(message, BUFFER_SIZE, stdin);
        str_trim_lf(message, BUFFER_SIZE);
        
        // Check for exit command
        if (strcmp(message, "/quit") == 0 || strcmp(message, "/exit") == 0) {
            running = 0;
            break;
        }
        
        // Skip empty messages
        if (strlen(message) == 0) {
            continue;
        }
        
        // Send message to server
        if (send(sockfd, message, strlen(message), 0) < 0) {
            perror("Send failed");
            running = 0;
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;
    pthread_t receive_thread;
    
    // Check command line arguments
    if (argc != 3) {
        printf("Usage: %s <server_address> <port>\n", argv[0]);
        printf("Example: %s csa.ramapo.edu 1111\n", argv[0]);
        printf("Example: %s 127.0.0.1 1111\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    char *server_ip = argv[1];
    int PORT = atoi(argv[2]);
    
    printf("=== Chat Room Client ===\n");
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    // Convert IP address from text to binary
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Connect to server
    printf("Connecting to %s:%d...\n", server_ip, PORT);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    printf("✓ Connected to server!\n");
    
    // Authenticate with server
    if (!authenticate_with_server()) {
        printf("Authentication failed. Disconnecting...\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    printf("\n=== Welcome to the Chat Room ===\n");
    printf("Commands:\n");
    printf("  /quit or /exit - Leave the chat\n");
    printf("================================\n\n");
    
    // Create thread for receiving messages
    if (pthread_create(&receive_thread, NULL, receive_messages, NULL) != 0) {
        perror("Thread creation failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Main thread handles sending messages
    send_message();
    
    // Cleanup
    printf("\nDisconnecting...\n");
    pthread_join(receive_thread, NULL);
    close(sockfd);
    printf("Goodbye!\n");
    
    return 0;
}