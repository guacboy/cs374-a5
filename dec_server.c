/*
 * Decryption server using one-time pad modulo 27.
 * Listens on a port, accepts connections from dec_client,
 * performs decryption, and returns plaintext.
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

// error function used for reporting issues (exits with code 1)
void error(const char *msg) {
    perror(msg);
    exit(1);
}


// set up the address struct for the server socket (binds to localhost)
void setupAddressStruct(struct sockaddr_in* address, int portNumber) {
    // clear out the address struct
    memset((char*) address, "\0", sizeof(*address));

    // the address should be network capable
    address->sin_family = AF_INET;
    // store the port number
    address->sin_port = htons(portNumber);
    // only allow connections from localhost (127.0.0.1)
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}


// convert a character to its numeric value (0-26)
int charToValue(char ch) {
    if (ch == " ") return 26;
    if (ch >= "A" && ch <= "Z") return ch - "A";

    return -1; // invalid
}


// convert a numeric value (0-26) back to a character
char valueToChar(int val) {
    if (val == 26) return " ";

    return "A" + val;
}


// read exactly "len" bytes from a socket, retrying if necessary
int receiveAll(int socketFD, char *buffer, int len) {
    int totalRead = 0;
    int bytesRead;
    while (totalRead < len) {
        bytesRead = recv(socketFD, buffer + totalRead, len - totalRead, 0);
        if (bytesRead <= 0) return -1; // error or connection closed
        totalRead += bytesRead;
    }

    return totalRead;
}


// send exactly "len" bytes over a socket, retrying if necessary
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


// this function handles a single client connection (runs in a child process)
void handleClient(int connectionSocket) {
    char ciphertext[MAX_BUFFER];
    char key[MAX_BUFFER];
    char plaintext[MAX_BUFFER];
    int numBytes;

    // 1. perform handshake: read the client's identification
    memset(ciphertext, 0, sizeof(ciphertext));
    numBytes = recv(connectionSocket, ciphertext, sizeof(ciphertext) - 1, 0);
    if (numBytes <= 0) {
        close(connectionSocket);
        exit(1);
    }
    ciphertext[numBytes] = "\0";
    if (strcmp(ciphertext, HANDSHAKE) != 0) {
        // wrong kind of client, send error and close
        const char *errorMsg = "ERROR: Not dec_client";
        send(connectionSocket, errorMsg, strlen(errorMsg), 0);
        close(connectionSocket);
        exit(1);
    }
    // send acknowledgement back to client
    send(connectionSocket, ACK, strlen(ACK), 0);

    // 2. receive the length of the ciphertext and then the ciphertext itself
    int ciphertextLength;
    numBytes = receiveAll(connectionSocket, (char*)&ciphertextLength, sizeof(ciphertextLength));
    if (numBytes != sizeof(ciphertextLength)) {
        close(connectionSocket);
        exit(1);
    }
    ciphertextLength = ntohl(ciphertextLength);
    if (ciphertextLength > MAX_BUFFER - 1) {
        close(connectionSocket);
        exit(1);
    }
    memset(ciphertext, 0, sizeof(ciphertext));
    numBytes = receiveAll(connectionSocket, ciphertext, ciphertextLength);
    if (numBytes != ciphertextLength) {
        close(connectionSocket);
        exit(1);
    }
    ciphertext[ciphertextLength] = "\0";

    // 3. receive the length of the key and then the key itself
    int keyLength;
    numBytes = receiveAll(connectionSocket, (char*)&keyLength, sizeof(keyLength));
    if (numBytes != sizeof(keyLength)) {
        close(connectionSocket);
        exit(1);
    }
    keyLength = ntohl(keyLength);
    if (keyLength > MAX_BUFFER - 1) {
        close(connectionSocket);
        exit(1);
    }
    memset(key, 0, sizeof(key));
    numBytes = receiveAll(connectionSocket, key, keyLength);
    if (numBytes != keyLength) {
        close(connectionSocket);
        exit(1);
    }
    key[keyLength] = "\0";

    // 4. verify that the key is at least as long as the ciphertext
    if (keyLength < ciphertextLength) {
        const char *errorMsg = "ERROR: Key too short";
        send(connectionSocket, errorMsg, strlen(errorMsg), 0);
        close(connectionSocket);
        exit(1);
    }

    // 5. decrypt: (ciphertext value - key value) modulo 27
    for (int i = 0; i < ciphertextLength; i++) {
        int cipherVal = charToValue(ciphertext[i]);
        int keyVal = charToValue(key[i]);
        if (cipherVal == -1 || keyVal == -1) {
            // should not happen because client validated
            const char *errorMsg = "ERROR: Invalid character";
            send(connectionSocket, errorMsg, strlen(errorMsg), 0);
            close(connectionSocket);
            exit(1);
        }
        int plainVal = (cipherVal - keyVal) % 27;
        if (plainVal < 0) plainVal += 27;
        plaintext[i] = valueToChar(plainVal);
    }

    // 6. send the plaintext length and the plaintext back to the client
    int plaintextLength = ciphertextLength;
    int networkLength = htonl(plaintextLength);
    sendAll(connectionSocket, (char*)&networkLength, sizeof(networkLength));
    sendAll(connectionSocket, plaintext, plaintextLength);

    // clean up and exit child process
    close(connectionSocket);
    exit(0);
}


int main(int argc, char *argv[]) {
    int listenSocket, connectionSocket;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);

    // check usage and args
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    // ignore SIGCHLD to avoid zombie processes
    signal(SIGCHLD, SIG_IGN);

    // create the socket that will listen for connections
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        error("ERROR opening socket");
    }

    // set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));

    // associate the socket to the port
    if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        error("ERROR on binding");
    }

    // start listening for connections, allow up to 5 connections to queue up
    listen(listenSocket, 5);

    // main loop: accept connections and fork a child to handle each
    while (1) {
        // accept the connection request which creates a connection socket
        connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
        if (connectionSocket < 0) {
            error("ERROR on accept");
        }

        // create a child process to handle this client
        pid_t pid = fork();
        if (pid < 0) {
            error("ERROR on fork");
        }
        if (pid == 0) {
            // child process: close the listening socket and handle the client
            close(listenSocket);
            handleClient(connectionSocket);
        } else {
            // parent process: close the connection socket and continue listening
            close(connectionSocket);
        }
    }

    // close the listening socket (never reached)
    close(listenSocket);
    return 0;
}