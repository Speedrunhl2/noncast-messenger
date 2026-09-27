#ifndef SERVER_LIB_H
#define SERVER_LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include "tls.h"
#include "RMP_lib.h"
#define MAX_OUTGOING 32


typedef struct {
	enum read_packet_state_server state;
	ssize_t income;
} client_information_server;

typedef struct{
        struct sockaddr_in address;
        int server_socket;
	char *onion_address;
	SSL_CTX *ctx;
	struct pollfd fds[5];
	SSL *ssl[4];
	client_information_server client[4];
	int nfds;
}server_information;

int server_init(server_information *server);

int write_all(unsigned char *buffer , SSL *ssl , ssize_t len);

int send_packet(packet *pack , server_information *server , int i);

int recv_packet(packet *pack , server_information *server , int i);

void server_stop(server_information *server);

void server_start(server_information *server , packet *pack);

#endif
