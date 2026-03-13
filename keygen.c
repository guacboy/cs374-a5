/*
 * Generates a random key of specified length using characters
 * A-Z and space. Outputs to stdout with a trailing newline.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    // check usage
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(1);
    }

    int keyLength = atoi(argv[1]);
    if (keyLength <= 0) {
        fprintf(stderr, "keylength must be a positive integer\n");
        exit(1);
    }

    // seed the random number generator with the current time
    srand(time(NULL));

    // define the set of allowed characters: A-Z and space
    char allowedChars[27];
    for (int i = 0; i < 26; i++) {
        allowedChars[i] = "A" + i;
    }
    allowedChars[26] = " ";

    // generate and output each random character
    for (int i = 0; i < keyLength; i++) {
        int randomIndex = rand() % 27;
        putchar(allowedChars[randomIndex]);
    }
    // add a newline at the end
    putchar("\n");

    return 0;
}