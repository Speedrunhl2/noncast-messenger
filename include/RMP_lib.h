#ifndef RMP_LIB_H
#define RMP_LIB_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

enum read_packet_state_server{
        READ_STATE_SER,
        READ_SIZE_SER,
        READ_PAYLOAD_SER,
	READ_USERNAME_SER,
	READ_USERNAME_LEN_SER,
};


enum send_packet_state_client{
        SEND_STATE,
        SEND_SIZE,
        SEND_PAYLOAD,
	SEND_USERNAME,
	SEND_USERNAME_LEN,
};

enum read_packet_state_client{
        READ_STATE_CL,
        READ_SIZE_CL,
        READ_PAYLOAD_CL,
	READ_USERNAME_CL,
	READ_USERNAME_LEN_CL,
};

enum chat_command{
	CMD_SEND_FILE,
        CMD_EXIT,
        CMD_NONE,
};


enum state{
	SEND_MESSAGE,
	SEND_DATA,
	EXIT,
};

typedef struct{
	uint8_t state;
	uint32_t size; //size of buffer
	uint32_t len; //sender len
	uint32_t filename_len;
}packet_header;

typedef struct{
	packet_header header;
	unsigned char filename[128];
	unsigned char buffer[4096];
	unsigned char sender[128];
}packet;

#endif
