#include "../include/client_lib.h"
#include "../include/tls.h"

int socks5_connect(int sock, const char *host, uint16_t port)
{
    unsigned char buffer[512];


    buffer[0] = 0x05;
    buffer[1] = 0x01;
    buffer[2] = 0x00;

    if (send(sock, buffer, 3, 0) != 3) {
        return -1;
	}
    if (recv(sock, buffer, 2, MSG_WAITALL) != 2) {
        return -1;
	}
	printf("SOCKS method: %02X %02X\n",buffer[0],buffer[1]);

    if (buffer[0] != 0x05 || buffer[1] != 0x00) {
        return -1;
	}

    int len = strlen(host);
	printf("%s %d\n" , host , port);
	printf("%d\n" , len);
    int pos = 0;

    buffer[pos++] = 0x05;
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x03;
    buffer[pos++] = len;

    memcpy(buffer + pos, host, len);
    pos += len;

    buffer[pos++] = port >> 8;
    buffer[pos++] = port & 0xff;

	printf("Sending SOCKS CONNECT...\n");


    if(send(sock, buffer, pos, 0) != pos) {
        return -1;
	}

	printf("Waiting for SOCKS CONNECT response...\n");

    if(recv(sock, buffer, 4, MSG_WAITALL) != 4) {
        return -1;
	}



	printf("SOCKS CONNECT: %02X %02X %02X %02X\n",buffer[0],buffer[1],buffer[2],buffer[3]);

    if(buffer[1] != 0x00) {
        printf("SOCKS5 failed REP=%02X\n", buffer[1]);
        return -1;
    }




    if(buffer[3] == 0x01) {

        if(recv(sock, buffer, 6, MSG_WAITALL) != 6)
            return -1;

    } else if(buffer[3] == 0x03) {

        if(recv(sock, buffer, 1, MSG_WAITALL) != 1)
            return -1;

        int domain_len = buffer[0];

        if(recv(sock, buffer, domain_len + 2, MSG_WAITALL) != domain_len + 2)
            return -1;

    } else if(buffer[3] == 0x04) {

        if(recv(sock, buffer, 18, MSG_WAITALL) != 18)
            return -1;
    }


    return 0;
}


int client_init(client_information *client , char *onion_address) {

	memset(&client->address , 0 , sizeof(client->address));
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	client->address.sin_family = AF_INET;
	client->address.sin_port = htons(9050);
	inet_pton(AF_INET , "127.0.0.1" , &client->address.sin_addr);
	client->onion_address = onion_address;
	client->port = 80;
	client->server_socket = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);

	if(client->server_socket < 0) {
		perror("socket");
		return -1;
	}

	if(connect(client->server_socket , (struct sockaddr*)&client->address, sizeof(client->address)) < 0) {
		perror("connect");
		close(client->server_socket);
		return -1;
	}


	setsockopt(client->server_socket,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

        if(socks5_connect(client->server_socket , client->onion_address , client->port) < 0) {
		fprintf(stderr, "SOCKS5 handshake failed\n");
                close(client->server_socket);
                return -1;
        }


	client->ctx = create_client_context();

	if(!client->ctx) {
		fprintf(stderr , "Context creation failed\n");
		ERR_print_errors_fp(stderr);
		close(client->server_socket);
		return -1;
	}

	client->ssl = SSL_new(client->ctx);

	if (!client->ssl) {
		ERR_print_errors_fp(stderr);
        	close(client->server_socket);
        	return -1;
	}

	if (SSL_set_fd(client->ssl, client->server_socket) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(client->ssl);
		SSL_CTX_free(client->ctx);
		close(client->server_socket);
		return -1;
	}

printf("Calling SSL_connect()...\n");
fflush(stdout);

int ret = SSL_connect(client->ssl);

printf("SSL_connect() returned %d\n", ret);
fflush(stdout);

	if (ret <= 0) {
    		int ssl_err = SSL_get_error(client->ssl, ret);

    		fprintf(stderr, "SSL_connect failed: ret=%d ssl_err=%d\n",
            	ret, ssl_err);

    		ERR_print_errors_fp(stderr);

    		SSL_free(client->ssl);
    		SSL_CTX_free(client->ctx);
    		close(client->server_socket);

    		return -1;
	}
                        client->check_state = READ_STATE_CL;
                        client->income = 0;

	printf("TLS handshake is good\n");

	printf("Establishing polls for stdin/stdout\n");

	return 1;
}

int write_all_client(SSL *ssl, unsigned char *buffer , ssize_t len , ssize_t *out) {

        while(len > *out) {

                int r = SSL_write(ssl , buffer+*out , len - *out);

                if(r > 0) {
                *out += r;
                continue;
                }


                int err = SSL_get_error(ssl, r);

                if (err == SSL_ERROR_WANT_READ) {
                        return 0;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                        return 15;
                }


                return -1;


        }

        return 1;
}


int send_packet_client(packet *pack , client_information *client) {

	int r;

	if(pack->header.size > sizeof(pack->buffer)) {
		return -1;
	}

	switch(client->send_state) {
		case SEND_STATE:
		{
			r = write_all_client(client->ssl , (unsigned char *)&pack->header.state, sizeof(pack->header.state) , &client->out);

			if(r != 1)return r;

			client->out = 0;
			client->send_state = SEND_USERNAME_LEN;

		}
                case SEND_USERNAME_LEN:
                {
                        r = write_all_client(client->ssl ,(unsigned char *)&pack->header.len, sizeof(pack->header.len) , &client->out);

                        if(r != 1)return r;

                        client->out = 0;
                        client->send_state = SEND_USERNAME;

                }
                case SEND_USERNAME:
                {
                        r = write_all_client(client->ssl , pack->sender, pack->header.len , &client->out);

                        if(r != 1)return r;

                        client->out = 0;
                        client->send_state = SEND_SIZE;
                }
		case SEND_SIZE:
		{
			uint32_t wire_size = htonl(pack->header.size);
                        r = write_all_client(client->ssl ,(unsigned char *)&wire_size, sizeof(wire_size) , &client->out);

                        if(r != 1)return r;

                        client->out = 0;
                        client->send_state = SEND_PAYLOAD;

		}
		case SEND_PAYLOAD:
                {
                        r = write_all_client(client->ssl , pack->buffer, pack->header.size , &client->out);

                        if(r != 1)return r;

                        client->out = 0;
                        client->send_state = SEND_STATE;
			return 1;
                }
	}


	return 1;

}


int recv_packet_client(packet *pack, client_information *client)
{
    while(1) {

        switch (client->check_state) {
        case READ_STATE_CL:
        {
            size_t need = sizeof(pack->header.state) - client->income;

            if (need == 0) {
                client->income = 0;
                client->check_state = READ_USERNAME_LEN_CL;
                continue;
            }

            int r = SSL_read(
                client->ssl,
                (unsigned char *)&pack->header.state + client->income,
                need
            );

            if (r > 0) {
                client->income += r;

                if (client->income == sizeof(pack->header.state)) {
                    client->income = 0;
                    client->check_state = READ_USERNAME_LEN_CL;
                }

                continue;
            }

            int err = SSL_get_error(client->ssl, r);

            if (err == SSL_ERROR_WANT_READ) {
                return 0;
            }

            if (err == SSL_ERROR_WANT_WRITE) {
                return 15;
            }

            if (err == SSL_ERROR_ZERO_RETURN) {
                return -1;
            }

            fprintf(stderr,
                    "SSL_read(READ_STATE): r=%d SSL_error=%d\n",
                    r, err);

            ERR_print_errors_fp(stderr);
            return -1;
        }

        case READ_USERNAME_LEN_CL:
        {

            int r = SSL_read(
                client->ssl,
                (unsigned char *)&pack->header.len + client->income,
                sizeof(pack->header.len) - client->income
            );

            if (r > 0) {
                client->income += r;

                if (client->income == sizeof(pack->header.len)) {
                    client->income = 0;
                    client->check_state = READ_USERNAME_CL;
                }

                continue;
            }

            int err = SSL_get_error(client->ssl, r);

            if (err == SSL_ERROR_WANT_READ) {
                return 0;
            }

            if (err == SSL_ERROR_WANT_WRITE) {
                return 15;
            }

            if (err == SSL_ERROR_ZERO_RETURN) {
                return -1;
            }

            fprintf(stderr,
                    "SSL_read(READ_STATE): r=%d SSL_error=%d\n",
                    r, err);

            ERR_print_errors_fp(stderr);
            return -1;
        }
	case READ_USERNAME_CL:
	{
		int r = SSL_read(client->ssl , pack->sender + client->income , pack->header.len - client->income);

		if(r > 0) {
			client->income += r;

			if(client->income == pack->header.len) {
				client->income = 0;
				client->check_state = READ_SIZE_CL;
			}
		continue;
		}
	int err = SSL_get_error(client->ssl , r);

	if(err == SSL_ERROR_WANT_READ) {
		return 0;
	}
        if(err == SSL_ERROR_WANT_WRITE) {
                return 15;
        }
        if(err == SSL_ERROR_ZERO_RETURN) {
                return -1;
        }
            fprintf(stderr,
                    "SSL_read(READ_STATE): r=%d SSL_error=%d\n",
                    r, err);

            ERR_print_errors_fp(stderr);
            return -1;


	}
        case READ_SIZE_CL:
        {
            size_t need = sizeof(pack->header.size) - client->income;

            if (need == 0) {
                client->income = 0;
                continue;
            }

            int r = SSL_read(
                client->ssl,
                (unsigned char *)&pack->header.size + client->income,
                need
            );

            if (r > 0) {
                client->income += r;

                if (client->income == sizeof(pack->header.size)) {
			pack->header.size = ntohl(pack->header.size);
/*
                    fprintf(stderr,
                            "[RECV] state=%u size=%u\n",
                            pack->header.state,
                            pack->header.size);
*/
                    client->income = 0;
		if (pack->header.size > sizeof(pack->buffer)) {
                        fprintf(stderr,
                                "ERROR: packet too large: %u > %zu\n",
                                pack->header.size,
                                sizeof(pack->buffer));

                        return -1;
                    }

                    if (pack->header.state == EXIT) {

                        if (pack->header.size != 0) {
                            fprintf(stderr,
                                    "ERROR: EXIT packet has size=%u\n",
                                    pack->header.size);

                            return -1;
                        }

                        client->check_state = READ_STATE_CL;
                        return 35;
                    }


                    if (pack->header.state == SEND_MESSAGE) {

                        if (pack->header.size == 0) {
                            client->check_state = READ_STATE_CL;
                            return 1;
                        }

                        client->check_state = READ_PAYLOAD_CL;
                        continue;
                    }

                    fprintf(stderr,
                            "ERROR: unknown packet state: %u\n",
                            pack->header.state);

                    return -1;
                }

                continue;
            }

            int err = SSL_get_error(client->ssl, r);

            if (err == SSL_ERROR_WANT_READ) {
                return 0;
            }

            if (err == SSL_ERROR_WANT_WRITE) {
                return 15;
            }

            if (err == SSL_ERROR_ZERO_RETURN) {
                fprintf(stderr, "TLS connection closed by peer\n");
                return -1;
            }

            fprintf(stderr,
                    "SSL_read(READ_SIZE): r=%d SSL_error=%d\n",
                    r, err);

            ERR_print_errors_fp(stderr);
            return -1;
        }


	case READ_PAYLOAD_CL:
        {

            if (client->income > pack->header.size) {
                fprintf(stderr,
                        "ERROR: income=%zu > packet size=%u\n",
                        client->income,
                        pack->header.size);

                return -1;
            }

            size_t remaining =
                (size_t)pack->header.size - client->income;


            if (remaining == 0) {
/*
                fprintf(stderr,
                        "[RECV] payload complete: %u bytes\n",
                        pack->header.size);
*/
                client->income = 0;
                client->check_state = READ_STATE_CL;

                return 1;
            }

            int r = SSL_read(
                client->ssl,
                pack->buffer + client->income,
                remaining
            );

            if (r > 0) {

                client->income += r;
/*
                fprintf(stderr,
                        "[RECV] payload: +%d -> %zu/%u\n",
                        r,
                        client->income,
                        pack->header.size);

*/
                if (client->income == pack->header.size) {
                    client->income = 0;
                    client->check_state = READ_STATE_CL;

                    return 1;
                }
                continue;
            }

            int err = SSL_get_error(client->ssl, r);

            if (err == SSL_ERROR_WANT_READ) {
                return 0;
            }

            if (err == SSL_ERROR_WANT_WRITE) {
                return 15;
            }

            if (err == SSL_ERROR_ZERO_RETURN) {
                fprintf(stderr,
                        "TLS connection closed during payload\n");
                return -1;
            }

            fprintf(stderr,
                    "SSL_read(READ_PAYLOAD): "
                    "r=%d SSL_error=%d "
                    "size=%u income=%zu remaining=%zu\n",
                    r,
                    err,
                    pack->header.size,
                    client->income,
                    remaining);

            ERR_print_errors_fp(stderr);

            return -1;
        }


        default:
        {
            fprintf(stderr,
                    "ERROR: invalid recv state: %d\n",
                    client->check_state);

            return -1;
        }
        }
    }
}

int parse_command(unsigned char *buffer) {

	buffer[strcspn((char *)buffer, "\n")] = '\0';

	if(strcmp((char *)buffer , "/exit") == 0) {
		return CMD_EXIT;
	}

	if(strcmp((char *)buffer , "/file") == 0) {
		return CMD_SEND_FILE;
	} //WIP

	return CMD_NONE;
}

void client_session(client_information *client , packet *pack) {

int flags = fcntl(client->server_socket, F_GETFL, 0);

	if (flags == -1) {
    		perror("fcntl");
    		return;
	}

	if (fcntl(client->server_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
    		perror("fcntl");
    		return;
	}

	struct pollfd fds[2];

       	fds[0].fd = STDIN_FILENO;
        fds[1].fd = SSL_get_fd(client->ssl);
        fds[0].events = POLLIN;
        fds[1].events = POLLIN;

	int status;
	int control;
	int sending = 0;
        while(1) {

		int ret = poll(fds , 2 , -1);

		if(ret <= 0) {
			perror("poll");
			break;
		}
/*
printf("poll returned: %d\n", ret);
printf("stdin revents:   0x%x\n", fds[0].revents);
printf("socket fd:       %d\n", fds[1].fd);
printf("socket revents:  0x%x\n", fds[1].revents);
*/
		if(fds[0].revents & POLLIN) {
			ssize_t r = read(0 , pack->buffer , 4095);

			if(r <= 0) {
				break;
			}


			pack->header.size = (uint32_t)r;
			pack->buffer[pack->header.size] = '\0';

			control = parse_command(pack->buffer);

			switch(control) {
				case CMD_EXIT:
					pack->header.state = EXIT;
					pack->header.size = 0;
					pack->header.len = 4;
                                        memcpy(pack->sender , "exit" , 4);
					client->send_state = SEND_STATE;
					client->out = 0;
					sending = 1;
					fds[1].events = POLLIN | POLLOUT;
					break;
				case CMD_NONE:
					pack->header.state = SEND_MESSAGE;
					pack->header.size = r;
					memcpy(pack->sender , client->data.username , client->data.username_len);
					pack->header.len = client->data.username_len;
                                        client->send_state = SEND_STATE;
                                        client->out = 0;
					sending = 1;
					fds[1].events = POLLIN | POLLOUT;
					break;
				default:
					fprintf(stderr, "Unknown command\n");
    					continue;
			}
		}

		if(sending == 1 && (fds[1].revents & (POLLIN | POLLOUT))) {
			status = send_packet_client(pack , client);

			if(status == 1) {
				sending = 0;
				fds[1].events = POLLIN;
			}
                        if(status < 0) {
                                sending = 0;
				goto cleanup;
				break;
                        }
                        if(status == 0) {
				sending = 1;
				fds[1].events = POLLIN;
                        }
                        if(status == 15) {
				sending = 1;
				fds[1].events = POLLOUT;
                        }


		}
if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
    fprintf(stderr,
            "socket error: revents=0x%x\n",
            fds[1].revents);
    break;
}
		if((fds[1].revents & POLLIN) && sending == 0) {
    //			printf(">>> SOCKET POLLIN\n");
    			fflush(stdout);
			status = recv_packet_client(pack , client);
    //			printf(">>> recv_packet returned: %d\n", status);
    			fflush(stdout);

               		if(status == 1) {
				printf(">[%.*s]%.*s\n", (int)pack->header.len , pack->sender , (int)pack->header.size, pack->buffer);
			}
			if(status == 35) {
				break;
			}

			if(status == 0) {
				fds[1].events = POLLIN;
				continue;
			}

			if(status == 15) {
				fds[1].events = POLLOUT;
				continue;
			}

			if(status < 0) {
				ERR_print_errors_fp(stderr);
				fprintf(stderr , "Failed packet receive");
				break;
			}
		}
        }

	cleanup:

	SSL_shutdown(client->ssl);
	SSL_free(client->ssl);
       	close(client->server_socket);
	SSL_CTX_free(client->ctx);
}

