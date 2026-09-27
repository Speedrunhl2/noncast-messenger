#ifndef CLIENT_LIB_H
#define CLIENT_LIB_H
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "RMP_lib.h"
#include <sodium.h>

typedef struct{
	unsigned char username[128];
	unsigned char hash[crypto_pwhash_STRBYTES];
	unsigned char id[128];
	ssize_t username_len;
	ssize_t hash_len;
	ssize_t id_len;
}client_data;

typedef struct{
        struct sockaddr_in address;
        int server_socket;
	char *onion_address;
	uint16_t port;
	SSL_CTX *ctx;
	SSL *ssl;
	enum read_packet_state_client check_state;
	enum send_packet_state_client send_state;
	client_data data;
	ssize_t income;
	ssize_t out;
}client_information;

int socks5_connect(int sock , const char *host , uint16_t port);

int client_init(client_information *client , char *onion_address);

int write_all_client(SSL *ssl, unsigned char *buffer , ssize_t len , ssize_t *out);

int send_packet_client(packet *pack , client_information *client);

int recv_packet_client(packet *pack , client_information *client);

int parse_command(unsigned char *buffer);

void client_session(client_information *client , packet *pack);

#endif
