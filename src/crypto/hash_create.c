#include "../../include/crypt_lib.h"

int hash_create(client_information *client , unsigned char buffer[] , ssize_t buffer_len) {
    if (crypto_pwhash_str(
            (char *)client->data.hash,
            (const char *)buffer,
            buffer_len,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        ) != 0) {

        return -1;
    }


	return 1; //worked
}

int id_create(client_information *client) {
	randombytes_buf(client->data.id , 128);
	return 1; //worked
}
