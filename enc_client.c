/*
 * Client for encryption server. Sends plaintext and key,
 * receives ciphertext.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define HANDSHAKE "ENC_CLIENT"
#define ACK "OK"
#define MAX_BUFFER 100000

// convert a character to its numeric value (0-26)
int character_to_value(char ch) {
    if (ch == " ") return 26;
    if (ch >= "A" && ch <= "Z") return ch - "A";
    
    return -1;
}


// read exactly "len" bytes from a socket
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


// send exactly "len" bytes over a socket
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


// read a file, remove trailing newline, and optionally validate characters
char* read_file(const char *filename, int *out_length, int should_validate) {
    FILE *file_pointer = fopen(filename, "r");

    if (!file_pointer) {
        perror("fopen");
        return NULL;
    }
    
    // determine file size
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

    // remove trailing newline if it exists
    if (file_size > 0 && file_content[file_size - 1] == "\n") {
        file_content[file_size - 1] = "\0";
        *out_length = file_size - 1;
    } else {
        file_content[file_size] = "\0";
        *out_length = file_size;
    }

    // if validation is requested, check every character
    if (should_validate) {
        for (int i = 0; i < *out_length; i++) {
            if (character_to_value(file_content[i]) == -1) {
                free(file_content);
                return NULL;  // bad character found
            }
        }
    }
    return file_content;
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    char *plaintext_filename = argv[1];
    char *key_filename = argv[2];
    int port_number = atoi(argv[3]);

    // read and validate the plaintext file
    int plaintext_length;
    char *plaintext = read_file(plaintext_filename, &plaintext_length, 1);
    if (!plaintext) {
        fprintf(stderr, "enc_client error: input contains bad characters or file error\n");
        exit(1);
    }

    // read and validate the key file
    int key_length;
    char *key = read_file(key_filename, &key_length, 1);
    if (!key) {
        fprintf(stderr, "enc_client error: key contains bad characters or file error\n");
        free(plaintext);
        exit(1);
    }

    // ensure the key is at least as long as the plaintext
    if (key_length < plaintext_length) {
        fprintf(stderr, "Error: key "%s" is too short\n", key_filename);
        free(plaintext);
        free(key);
        exit(1);
    }

    // create a socket and connect to the server
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        free(plaintext);
        free(key);
        exit(2);
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port_number);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", port_number);
        close(socket_fd);
        free(plaintext);
        free(key);
        exit(2);
    }

    // perform handshake: send our identifier
    send_all(socket_fd, HANDSHAKE, strlen(HANDSHAKE));

    // wait for acknowledgement from server
    char ack_buffer[16];
    int bytes_received = recv(socket_fd, ack_buffer, sizeof(ack_buffer) - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "Error: no response from server\n");
        close(socket_fd);
        free(plaintext);
        free(key);
        exit(2);
    }

    ack_buffer[bytes_received] = "\0";
    if (strcmp(ack_buffer, ACK) != 0) {
        fprintf(stderr, "Error: connected to wrong server (got %s)\n", ack_buffer);
        close(socket_fd);
        free(plaintext);
        free(key);
        exit(2);
    }

    // send the plaintext length and the plaintext itself
    int network_length = htonl(plaintext_length);
    send_all(socket_fd, (char*)&network_length, sizeof(network_length));
    send_all(socket_fd, plaintext, plaintext_length);

    // send the key length and the key itself
    network_length = htonl(key_length);
    send_all(socket_fd, (char*)&network_length, sizeof(network_length));
    send_all(socket_fd, key, key_length);

    // receive the ciphertext length and then the ciphertext
    int ciphertext_length;
    bytes_received = receive_all(socket_fd, (char*)&ciphertext_length, sizeof(ciphertext_length));
    if (bytes_received != sizeof(ciphertext_length)) {
        fprintf(stderr, "Error: failed to receive cipher length\n");
        close(socket_fd);
        free(plaintext);
        free(key);
        exit(1);
    }
    ciphertext_length = ntohl(ciphertext_length);
    char ciphertext[MAX_BUFFER];

    bytes_received = receive_all(socket_fd, ciphertext, ciphertext_length);
    if (bytes_received != ciphertext_length) {
        fprintf(stderr, "Error: failed to receive ciphertext\n");
        close(socket_fd);
        free(plaintext);
        free(key);
        exit(1);
    }
    ciphertext[ciphertext_length] = "\0";

    // output the ciphertext with a trailing newline
    printf("%s\n", ciphertext);

    // clean up
    close(socket_fd);
    free(plaintext);
    free(key);
    return 0;
}