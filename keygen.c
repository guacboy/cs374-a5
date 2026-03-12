/*
 * Generates a random key of specified length using characters
 * A-Z and space. Outputs to stdout with a trailing newline.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(1);
    }

    int key_length = atoi(argv[1]);
    if (key_length <= 0) {
        fprintf(stderr, "keylength must be a positive integer\n");
        exit(1);
    }

    // seed the random number generator with the current time
    srand(time(NULL));

    // define the set of allowed characters: A-Z and space
    char allowed_characters[27];
    for (int i = 0; i < 26; i++) {
        allowed_characters[i] = 'A' + i;
    }
    allowed_characters[26] = ' ';

    // generate and output each random character
    for (int i = 0; i < key_length; i++) {
        int random_index = rand() % 27;
        putchar(allowed_characters[random_index]);
    }
    // add a newline at the end
    putchar('\n');

    return 0;
}