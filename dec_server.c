/*
 * Decryption server using one-time pad modulo 27.
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
#define HANDSHAKE "DEC_CLIENT"
#define ACK "OK"

int character_to_value(char ch) {
    if (ch == " ") return 26;
    if (ch >= "A" && ch <= "Z") return ch - "A";

    return -1;
}


char value_to_character(int value) {
    if (value == 26) return " ";
    
    return "A" + value;
}


int receive_all(int socket_fd, char *buffer, int len) {
    int total_read = 0;
    int bytes_this_time;
    while (total_read < len) {
        bytes_this_time = recv(socket_fd, buffer + total_read, len - total_read, 0);
        
        if (bytes_this_time <= 0) return -1;
        total_read += bytes_this_time;
    }

    return total_read;
}


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


void handle_client_connection(int client_socket) {
    char ciphertext[MAX_BUFFER];
    char key[MAX_BUFFER];
    char plaintext[MAX_BUFFER];
    int num_bytes;

    // handshake: identify the client
    memset(ciphertext, 0, sizeof(ciphertext));
    num_bytes = recv(client_socket, ciphertext, sizeof(ciphertext) - 1, 0);
    if (num_bytes <= 0) {
        close(client_socket);
        exit(1);
    }

    ciphertext[num_bytes] = "\0";
    if (strcmp(ciphertext, HANDSHAKE) != 0) {
        const char *error_msg = "ERROR: Not dec_client";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        exit(1);
    }
    send(client_socket, ACK, strlen(ACK), 0);

    // receive ciphertext length and ciphertext
    int ciphertext_length;
    num_bytes = receive_all(client_socket, (char*)&ciphertext_length, sizeof(ciphertext_length));
    if (num_bytes != sizeof(ciphertext_length)) {
        close(client_socket);
        exit(1);
    }
    ciphertext_length = ntohl(ciphertext_length);

    if (ciphertext_length > MAX_BUFFER - 1) {
        close(client_socket);
        exit(1);
    }
    memset(ciphertext, 0, sizeof(ciphertext));

    num_bytes = receive_all(client_socket, ciphertext, ciphertext_length);
    if (num_bytes != ciphertext_length) {
        close(client_socket);
        exit(1);
    }
    ciphertext[ciphertext_length] = "\0";

    // receive key length and key
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

    // check that key is at least as long as ciphertext
    if (key_length < ciphertext_length) {
        const char *error_msg = "ERROR: Key too short";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        exit(1);
    }

    // decrypt: (ciphertext value - key value) modulo 27
    for (int i = 0; i < ciphertext_length; i++) {
        int cipher_val = character_to_value(ciphertext[i]);
        int key_val = character_to_value(key[i]);

        if (cipher_val == -1 || key_val == -1) {
            const char *error_msg = "ERROR: Invalid character";
            send(client_socket, error_msg, strlen(error_msg), 0);
            close(client_socket);
            exit(1);
        }

        int plain_val = (cipher_val - key_val) % 27;
        if (plain_val < 0) plain_val += 27;
        plaintext[i] = value_to_character(plain_val);
    }

    // send back the plaintext length and plaintext
    int plaintext_length = ciphertext_length;
    int network_length = htonl(plaintext_length);
    send_all(client_socket, (char*)&network_length, sizeof(network_length));
    send_all(client_socket, plaintext, plaintext_length);

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

    signal(SIGCHLD, SIG_IGN);

    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket < 0) {
        perror("socket");
        exit(1);
    }

    int reuse_option = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &reuse_option, sizeof(reuse_option));

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_address.sin_port = htons(port_number);

    if (bind(listen_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("bind");
        close(listen_socket);
        exit(1);
    }

    if (listen(listen_socket, 5) < 0) {
        perror("listen");
        close(listen_socket);
        exit(1);
    }

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
            close(listen_socket);
            handle_client_connection(client_socket);
        } else {
            close(client_socket);
        }
    }

    close(listen_socket);
    return 0;
}