/*
 * Client for decryption server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HANDSHAKE "DEC_CLIENT"
#define ACK "OK"
#define MAX_BUFFER 100000

int character_to_value(char ch) {
    if (ch == " ") return 26;
    if (ch >= "A" && ch <= "Z") return ch - "A";

    return -1;
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


char* read_file(const char *filename, int *out_length, int should_validate) {
    FILE *file_pointer = fopen(filename, "r");

    if (!file_pointer) {
        perror("fopen");
        return NULL;
    }

    fseek(file_pointer, 0, SEEK_END);
    long file_size = ftell(file_pointer);
    rewind(file_pointer);

    char *file_content = malloc(file_size + 1);
    if (!file_content) {
        fclose(file_pointer);
        return NULL;
    }

    size_t bytes_read = fread(file_content, 1, file_size, file_pointer);
    fclose(file_pointer);
    if (bytes_read != file_size) {
        free(file_content);
        return NULL;
    }

    if (file_size > 0 && file_content[file_size - 1] == "\n") {
        file_content[file_size - 1] = "\0";
        *out_length = file_size - 1;
    } else {
        file_content[file_size] = "\0";
        *out_length = file_size;
    }

    if (should_validate) {
        for (int i = 0; i < *out_length; i++) {
            if (character_to_value(file_content[i]) == -1) {
                free(file_content);
                return NULL;
            }
        }
    }

    return file_content;
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s ciphertext key port\n", argv[0]);
        exit(1);
    }

    char *ciphertext_filename = argv[1];
    char *key_filename = argv[2];
    int port_number = atoi(argv[3]);

    int ciphertext_length;
    char *ciphertext = read_file(ciphertext_filename, &ciphertext_length, 1);
    if (!ciphertext) {
        fprintf(stderr, "dec_client error: input contains bad characters or file error\n");
        exit(1);
    }

    int key_length;
    char *key = read_file(key_filename, &key_length, 1);
    if (!key) {
        fprintf(stderr, "dec_client error: key contains bad characters or file error\n");
        free(ciphertext);
        exit(1);
    }

    if (key_length < ciphertext_length) {
        fprintf(stderr, "Error: key "%s" is too short\n", key_filename);
        free(ciphertext);
        free(key);
        exit(1);
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        free(ciphertext);
        free(key);
        exit(2);
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port_number);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        fprintf(stderr, "Error: could not contact dec_server on port %d\n", port_number);
        close(socket_fd);
        free(ciphertext);
        free(key);
        exit(2);
    }

    send_all(socket_fd, HANDSHAKE, strlen(HANDSHAKE));
    char ack_buffer[16];
    int bytes_received = recv(socket_fd, ack_buffer, sizeof(ack_buffer) - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "Error: no response from server\n");
        close(socket_fd);
        free(ciphertext);
        free(key);
        exit(2);
    }
    
    ack_buffer[bytes_received] = "\0";
    if (strcmp(ack_buffer, ACK) != 0) {
        fprintf(stderr, "Error: connected to wrong server (got %s)\n", ack_buffer);
        close(socket_fd);
        free(ciphertext);
        free(key);
        exit(2);
    }

    int network_length = htonl(ciphertext_length);
    send_all(socket_fd, (char*)&network_length, sizeof(network_length));
    send_all(socket_fd, ciphertext, ciphertext_length);

    network_length = htonl(key_length);
    send_all(socket_fd, (char*)&network_length, sizeof(network_length));
    send_all(socket_fd, key, key_length);

    int plaintext_length;
    bytes_received = receive_all(socket_fd, (char*)&plaintext_length, sizeof(plaintext_length));
    if (bytes_received != sizeof(plaintext_length)) {
        fprintf(stderr, "Error: failed to receive plaintext length\n");
        close(socket_fd);
        free(ciphertext);
        free(key);
        exit(1);
    }

    plaintext_length = ntohl(plaintext_length);
    char plaintext[MAX_BUFFER];
    bytes_received = receive_all(socket_fd, plaintext, plaintext_length);
    if (bytes_received != plaintext_length) {
        fprintf(stderr, "Error: failed to receive plaintext\n");
        close(socket_fd);
        free(ciphertext);
        free(key);
        exit(1);
    }
    plaintext[plaintext_length] = "\0";

    printf("%s\n", plaintext);

    close(socket_fd);
    free(ciphertext);
    free(key);
    return 0;
}