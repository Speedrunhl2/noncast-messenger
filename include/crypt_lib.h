#include "client_lib.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sodium.h>

int hash_create(client_information *client , unsigned char buffer[] , ssize_t buffer_len);

int id_create(client_information *client);
