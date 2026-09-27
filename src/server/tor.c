#include "../include/tor.h"

char *create_onion_address() {

	struct sockaddr_in con;
	memset(&con , 0 , sizeof(con));
	char *auth = "AUTHENTICATE \"PUT PASSWORD HERE\" \r\n";
	char buffer[512];
	char *signal = "ADD_ONION NEW:ED25519-V3 Flags=Detach Port=80,127.0.0.1:8080\r\n";
	char *onion = calloc(64 , sizeof(char));

	con.sin_port = htons(9051);
	con.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1" , &con.sin_addr);

	int fd = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);

	if(fd < 0) {
		return NULL;
	}

	if(connect(fd , (struct sockaddr*)&con , sizeof(con)) < 0) {
		close(fd);
		return NULL;
	}

	send(fd , auth , strlen(auth) , 0);

	ssize_t r = recv(fd , buffer , 511 , 0);

	if(r <= 0) {
		close(fd);
		return NULL;
	}

	buffer[r] = '\0';

	if (strncmp(buffer, "250", 3) != 0) {
		fprintf(stderr, "Authentication failed: %s\n", buffer);
		close(fd);
		free(onion);
		return NULL;
	}



	printf("%s\n" , buffer);
	memset(&buffer  , 0 , sizeof(buffer));

	send(fd , signal , strlen(signal) , 0);
	ssize_t lq = recv(fd , buffer , 511 , 0);

	if(lq <= 0) {
		close(fd);
		return NULL;
	}

	buffer[lq] = '\0';
	printf("Tor reply:\n%s\n", buffer);

	char *service = strstr(buffer , "ServiceID=");

	if(service == NULL) {
		close(fd);
		free(onion);
		return NULL;
	}

	service += strlen("ServiceID=");
	sscanf(service , "%63s" , onion);
	strcat(onion, ".onion");
	printf("Onion created: %s\n", onion);
	printf("Tor should forward %s:80 -> 127.0.0.1:8080\n", onion);
	close(fd);
	return onion;

}
