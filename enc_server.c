/*
 * Encryption server using one-time pad modulo 27.
 * Listens on a port, accepts connections from enc_client,
 * performs encryption, and returns ciphertext.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define MAX_BUFFER 100000
#define HANDSHAKE "ENC_CLIENT"
#define ACK "OK"

// convert a character to its numeric value
int character_to_value(char ch) {
    if (ch == " ") return 26;
    if (ch >= "A" && ch <= "Z") return ch - "A";

    return -1;  // invalid character
}


// convert a numeric value (0-26) back to a character
char value_to_character(int value) {
    if (value == 26) return " ";

    return "A" + value;
}


// read exactly "len" bytes from a socket, retrying if necessary
int receive_all(int socket_fd, char *buffer, int len) {
    int total_read = 0;
    int bytes_this_time;
    while (total_read < len) {
        bytes_this_time = recv(socket_fd, buffer + total_read, len - total_read, 0);

        if (bytes_this_time <= 0) return -1;  // error or connection closed
        total_read += bytes_this_time;
    }

    return total_read;
}


// send exactly "len" bytes over a socket, retrying if necessary
int send_all(int socket_fd, const char *buffer, int len) {
    int total_sent = 0;
    int bytes_this_time;
    while (total_sent < len) {
        bytes_this_time = send(socket_fd, buffer + total_sent, len - total_sent, 0);

        if (bytes_this_time <= 0) return -1;
        total_sent += bytes_this_time;
    }

    return total_sent;
}


// handles a single client connection (runs in a child process)
void handle_client_connection(int client_socket) {
    char plaintext[MAX_BUFFER];
    char key[MAX_BUFFER];
    char ciphertext[MAX_BUFFER];
    int num_bytes;

    // 1. perform handshake: read the client's identification
    memset(plaintext, 0, sizeof(plaintext));
    num_bytes = recv(client_socket, plaintext, sizeof(plaintext) - 1, 0);
    if (num_bytes <= 0) {
        close(client_socket);
        exit(1);
    }

    plaintext[num_bytes] = "\0";
    if (strcmp(plaintext, HANDSHAKE) != 0) {
        // wrong kind of client, send error and close
        const char *error_msg = "ERROR: Not enc_client";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        exit(1);
    }

    // send acknowledgement back to client
    send(client_socket, ACK, strlen(ACK), 0);

    // 2. receive the length of the plaintext and then the plaintext itself
    int plaintext_length;
    num_bytes = receive_all(client_socket, (char*)&plaintext_length, sizeof(plaintext_length));
    if (num_bytes != sizeof(plaintext_length)) {
        close(client_socket);
        exit(1);
    }

    plaintext_length = ntohl(plaintext_length);
    if (plaintext_length > MAX_BUFFER - 1) {
        close(client_socket);
        exit(1);
    }

    memset(plaintext, 0, sizeof(plaintext));
    num_bytes = receive_all(client_socket, plaintext, plaintext_length);
    if (num_bytes != plaintext_length) {
        close(client_socket);
        exit(1);
    }
    plaintext[plaintext_length] = "\0";

    // 3. receive the length of the key and then the key itself
    int key_length;
    num_bytes = receive_all(client_socket, (char*)&key_length, sizeof(key_length));
    if (num_bytes != sizeof(key_length)) {
        close(client_socket);
        exit(1);
    }

    key_length = ntohl(key_length);
    if (key_length > MAX_BUFFER - 1) {
        close(client_socket);
        exit(1);
    }

    memset(key, 0, sizeof(key));
    num_bytes = receive_all(client_socket, key, key_length);
    if (num_bytes != key_length) {
        close(client_socket);
        exit(1);
    }
    key[key_length] = "\0";

    // 4. verify that the key is at least as long as the plaintext
    if (key_length < plaintext_length) {
        const char *error_msg = "ERROR: Key too short";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        exit(1);
    }

    // 5. encrypt: (plaintext value + key value) modulo 27
    for (int i = 0; i < plaintext_length; i++) {
        int plain_val = character_to_value(plaintext[i]);
        int key_val = character_to_value(key[i]);

        if (plain_val == -1 || key_val == -1) {
            // should not happen because client validated
            const char *error_msg = "ERROR: Invalid character";
            send(client_socket, error_msg, strlen(error_msg), 0);
            close(client_socket);
            exit(1);
        }

        int cipher_val = (plain_val + key_val) % 27;
        ciphertext[i] = value_to_character(cipher_val);
    }

    // 6. send the ciphertext length and the ciphertext back to the client
    int ciphertext_length = plaintext_length;
    int network_length = htonl(ciphertext_length);
    send_all(client_socket, (char*)&network_length, sizeof(network_length));
    send_all(client_socket, ciphertext, ciphertext_length);

    // clean up and exit child process
    close(client_socket);
    exit(0);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s listening_port\n", argv[0]);
        exit(1);
    }

    int port_number = atoi(argv[1]);
    int listen_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_length = sizeof(client_address);

    // ignore SIGCHLD to avoid zombie processes
    signal(SIGCHLD, SIG_IGN);

    // create the listening socket
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket < 0) {
        perror("socket");
        exit(1);
    }

    // allow reuse of the address (useful for quick restarts)
    int reuse_option = 1;
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &reuse_option, sizeof(reuse_option)) < 0) {
        perror("setsockopt");
        close(listen_socket);
        exit(1);
    }

    // set up the server address structure
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // localhost
    server_address.sin_port = htons(port_number);

    // bind the socket to the port
    if (bind(listen_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("bind");
        close(listen_socket);
        exit(1);
    }

    // start listening for connections (allow up to 5 pending)
    if (listen(listen_socket, 5) < 0) {
        perror("listen");
        close(listen_socket);
        exit(1);
    }

    // main loop: accept incoming connections and fork a child to handle each
    while (1) {
        client_socket = accept(listen_socket, (struct sockaddr*)&client_address, &client_address_length);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        pid_t process_id = fork();
        if (process_id < 0) {
            perror("fork");
            close(client_socket);
            continue;
        }

        if (process_id == 0) {
            // this is the child process
            close(listen_socket);  // child doesn't need the listening socket
            handle_client_connection(client_socket);
        } else {
            // parent process: close the client socket and continue listening
            close(client_socket);
        }
    }

    close(listen_socket);
    return 0;
}
