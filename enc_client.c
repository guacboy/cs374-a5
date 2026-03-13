/*
 * Client for encryption server. Sends plaintext and key,
 * receives ciphertext.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define HANDSHAKE "ENC_CLIENT"
#define ACK "OK"
#define MAX_BUFFER 100000

// error function used for reporting issues (exits with given code)
void errorWithCode(const char *msg, int code) {
    perror(msg);
    exit(code);
}


// set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname) {
    // clear out the address struct
    memset((char*) address, "\0", sizeof(*address));

    // the address should be network capable
    address->sin_family = AF_INET;
    // store the port number
    address->sin_port = htons(portNumber);

    // get the DNS entry for this host name
    struct hostent* hostInfo = gethostbyname(hostname);
    if (hostInfo == NULL) {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(2);
    }
    // copy the first IP address from the DNS entry to sin_addr.s_addr
    memcpy((char*) &address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}


// convert a character to its numeric value (0-26)
int charToValue(char ch) {
    if (ch == " ") return 26;
    if (ch >= "A" && ch <= "Z") return ch - "A";
    return -1;
}


// read exactly "len" bytes from a socket
int receiveAll(int socketFD, char *buffer, int len) {
    int totalRead = 0;
    int bytesRead;
    while (totalRead < len) {
        bytesRead = recv(socketFD, buffer + totalRead, len - totalRead, 0);
        if (bytesRead <= 0) return -1;
        totalRead += bytesRead;
    }

    return totalRead;
}


// send exactly "len" bytes over a socket
int sendAll(int socketFD, const char *buffer, int len) {
    int totalSent = 0;
    int bytesSent;
    while (totalSent < len) {
        bytesSent = send(socketFD, buffer + totalSent, len - totalSent, 0);
        if (bytesSent <= 0) return -1;
        totalSent += bytesSent;
    }

    return totalSent;
}


// read a file, remove trailing newline, and optionally validate characters
char* readFile(const char *filename, int *outLength, int shouldValidate) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return NULL;
    }
    // determine file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    char *content = malloc(fileSize + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    size_t bytesRead = fread(content, 1, fileSize, file);
    fclose(file);
    if (bytesRead != fileSize) {
        free(content);
        return NULL;
    }

    // remove trailing newline if it exists
    if (fileSize > 0 && content[fileSize - 1] == "\n") {
        content[fileSize - 1] = "\0";
        *outLength = fileSize - 1;
    } else {
        content[fileSize] = "\0";
        *outLength = fileSize;
    }

    // if validation is requested, check every character
    if (shouldValidate) {
        for (int i = 0; i < *outLength; i++) {
            if (charToValue(content[i]) == -1) {
                free(content);
                return NULL; // bad character found
            }
        }
    }

    return content;
}


int main(int argc, char *argv[]) {
    int socketFD, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    char buffer[MAX_BUFFER];

    // check usage & args
    if (argc < 4) {
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    char *plaintextFile = argv[1];
    char *keyFile = argv[2];
    int portNumber = atoi(argv[3]);

    // read and validate the plaintext file
    int plaintextLength;
    char *plaintext = readFile(plaintextFile, &plaintextLength, 1);
    if (!plaintext) {
        fprintf(stderr, "enc_client error: input contains bad characters or file error\n");
        exit(1);
    }

    // read and validate the key file
    int keyLength;
    char *key = readFile(keyFile, &keyLength, 1);
    if (!key) {
        fprintf(stderr, "enc_client error: key contains bad characters or file error\n");
        free(plaintext);
        exit(1);
    }

    // ensure the key is at least as long as the plaintext
    if (keyLength < plaintextLength) {
        fprintf(stderr, "Error: key "%s" is too short\n", keyFile);
        free(plaintext);
        free(key);
        exit(1);
    }

    // create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        errorWithCode("CLIENT: ERROR opening socket", 2);
    }

    // set up the server address struct (use localhost as hostname)
    setupAddressStruct(&serverAddress, portNumber, "localhost");

    // connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portNumber);
        close(socketFD);
        free(plaintext);
        free(key);
        exit(2);
    }

    // perform handshake: send our identifier
    sendAll(socketFD, HANDSHAKE, strlen(HANDSHAKE));

    // wait for acknowledgement from server
    memset(buffer, 0, sizeof(buffer));
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (charsRead <= 0) {
        fprintf(stderr, "Error: no response from server\n");
        close(socketFD);
        free(plaintext);
        free(key);
        exit(2);
    }
    buffer[charsRead] = "\0";
    if (strcmp(buffer, ACK) != 0) {
        fprintf(stderr, "Error: connected to wrong server (got %s)\n", buffer);
        close(socketFD);
        free(plaintext);
        free(key);
        exit(2);
    }

    // send the plaintext length and the plaintext itself
    int networkLength = htonl(plaintextLength);
    sendAll(socketFD, (char*)&networkLength, sizeof(networkLength));
    sendAll(socketFD, plaintext, plaintextLength);

    // send the key length and the key itself
    networkLength = htonl(keyLength);
    sendAll(socketFD, (char*)&networkLength, sizeof(networkLength));
    sendAll(socketFD, key, keyLength);

    // receive the ciphertext length and then the ciphertext
    int ciphertextLength;
    charsRead = receiveAll(socketFD, (char*)&ciphertextLength, sizeof(ciphertextLength));
    if (charsRead != sizeof(ciphertextLength)) {
        fprintf(stderr, "Error: failed to receive cipher length\n");
        close(socketFD);
        free(plaintext);
        free(key);
        exit(1);
    }
    ciphertextLength = ntohl(ciphertextLength);
    char ciphertext[MAX_BUFFER];
    charsRead = receiveAll(socketFD, ciphertext, ciphertextLength);
    if (charsRead != ciphertextLength) {
        fprintf(stderr, "Error: failed to receive ciphertext\n");
        close(socketFD);
        free(plaintext);
        free(key);
        exit(1);
    }
    ciphertext[ciphertextLength] = "\0";

    // output the ciphertext with a trailing newline
    printf("%s\n", ciphertext);

    // close the socket and free memory
    close(socketFD);
    free(plaintext);
    free(key);
    return 0;
}