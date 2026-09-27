#include "../include/client_lib.h"
#include "../include/server_lib.h"
#include "../include/crypt_lib.h"

int main(void)
{
    int choice;
    char emblem[64][64];

    unsigned char password[64];
    char dot_onion[100];

    packet pack = {0};
    client_information client = {0};
    server_information server = {0};

    /*
     * Read username
     */

    printf("write username: ");
    fflush(stdout);
    ssize_t read_1 = read(
        STDIN_FILENO,
        client.data.username,
        sizeof(client.data.username) - 1
    );

    if (read_1 < 0) {
        perror("read username");
        return EXIT_FAILURE;
    }

    if (read_1 == 0) {
        fprintf(stderr, "No username entered\n");
        return EXIT_FAILURE;
    }

    /*
     * Remove newline if the user pressed Enter.
     */
    if (client.data.username[read_1 - 1] == '\n') {
        read_1--;
    }

    client.data.username[read_1] = '\0';
    client.data.username_len = read_1;


    /*
     * Read password
     */
    printf("write password: ");
    fflush(stdout);
    ssize_t read_2 = read(
        STDIN_FILENO,
        password,
        sizeof(password) - 1
    );

    if (read_2 < 0) {
        perror("read password");
        return EXIT_FAILURE;
    }

    if (read_2 == 0) {
        fprintf(stderr, "No password entered\n");
        return EXIT_FAILURE;
    }

    /*
     * Remove newline.
     */
    if (password[read_2 - 1] == '\n') {
        read_2--;
    }

    if (read_2 < 8) {
        fprintf(stderr, "Password must be at least 8 characters\n");
        return EXIT_FAILURE;
    }


    /*
     * Create password hash and ID.
     */
    if (hash_create(&client, password, read_2) != 1) {
        fprintf(stderr, "Failed to create password hash\n");
        return EXIT_FAILURE;
    }

    if (id_create(&client) != 1) {
        fprintf(stderr, "Failed to create client ID\n");
        return EXIT_FAILURE;
    }


    /*
     * Select mode.
     */
    printf("[1] - create server | [2] - connect to server\n");
    printf("write a choice: ");
    fflush(stdout);
    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid choice\n");
        return EXIT_FAILURE;
    }

    switch (choice) {

        case 1:
            if (server_init(&server) != 1) {
                fprintf(stderr, "server_init failed\n");
                return EXIT_FAILURE;
            }

            server_start(&server, &pack);
            break;


        case 2:
            printf("tell me .onion address of the server to connect: ");
	    fflush(stdout);
            if (scanf("%99s", dot_onion) != 1) {
                fprintf(stderr, "Invalid onion address\n");
                return EXIT_FAILURE;
            }

            if (client_init(&client, dot_onion) != 1) {
                fprintf(stderr, "client_init failed\n");
                return EXIT_FAILURE;
            }

            client_session(&client, &pack);
            break;


        default:
            fprintf(stderr, "wrong number\n");
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
