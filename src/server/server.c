#include "../include/server_lib.h"
#include "../include/tls.h"
#include "../include/tor.h"

int server_init(server_information *server) {

  memset(&server->address, 0, sizeof(server->address));
  server->address.sin_family = AF_INET;
  server->address.sin_port = htons(8080);
  server->address.sin_addr.s_addr = INADDR_ANY;
  server->server_socket = -1;

  server->server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (server->server_socket < 0) {
    perror("socket");
    free(server->onion_address);
    return -1;
  }

  server->ctx = create_context();

  if (!server->ctx) {
    close(server->server_socket);
    free(server->onion_address);
    fprintf(stderr, "Failed with creating context");
    return -1;
  }

  int opt = 1;

  if (setsockopt(server->server_socket, SOL_SOCKET, SO_REUSEADDR,
               &opt, sizeof(opt)) < 0) {
      perror("setsockopt");
      close(server->server_socket);
      return -1;
  }

  printf("Binding 127.0.0.1:8080...\n");

  int server_bind =
      bind(server->server_socket, (struct sockaddr *)&server->address,
           sizeof(server->address));

  if (server_bind < 0) {
    perror("bind");
    close(server->server_socket);
    SSL_CTX_free(server->ctx);
    free(server->onion_address);
    return -1;
  }

  printf("bind OK\n");

  server->onion_address = create_onion_address();

  if (server->onion_address == NULL) {
    fprintf(stderr, "Failed with creating .onion address");
    return -1;
  }

  printf(">>%s<<\n", server->onion_address);

  if (listen(server->server_socket, 5) < 0) {
    perror("listen");
    close(server->server_socket);
    SSL_CTX_free(server->ctx);
    free(server->onion_address);
    return -1;
  }

  printf("listening on %d\n", server->server_socket);
  printf("Server is listening on 127.0.0.1:8080\n");
  server->fds[0].fd = server->server_socket;
  server->fds[0].events = POLLIN;
  server->nfds = 1;

  return 1;
}

int write_all(unsigned char *buffer, SSL *ssl, ssize_t len) {

  ssize_t general = 0;

  while (len > general) {

    int r = SSL_write(ssl, buffer + general, len - general);

    if (r > 0) {
      general += r;
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

int send_packet(packet *pack, server_information *server , int i) {

  int check;

  check = write_all((unsigned char *)&pack->header.state, server->ssl[i],
                    sizeof(pack->header.state));

  if (check != 1) {
    return check;
  }


  check = write_all((unsigned char* )&pack->header.len, server->ssl[i],
                    sizeof(pack->header.len));

  if (check != 1) {
    return check;
  }

  check = write_all(pack->sender , server->ssl[i] , pack->header.len);

  if(check != 1) {
   return check;
  }

uint32_t wire_size = htonl(pack->header.size);

  check = write_all((unsigned char *)&wire_size, server->ssl[i],
                    sizeof(wire_size));

  if (check != 1) {
    return check;
  }


  check = write_all(pack->buffer, server->ssl[i], pack->header.size);

  if (check != 1) {
    return check;
  }



  return 1;
}

int recv_packet(packet *pack , server_information *server , int i) {

	while(1) {
		switch(server->client[i].state) {

			case READ_STATE_SER:
			{

				ssize_t r = SSL_read(server->ssl[i] , (unsigned char *)&pack->header.state + server->client[i].income , sizeof(pack->header.state) - server->client[i].income);
				if(r > 0) {
					server->client[i].income += r;
					if(server->client[i].income == sizeof(pack->header.state)) {
						server->client[i].income = 0;
						server->client[i].state = READ_USERNAME_LEN_SER;
					}
					continue;
				}
	                	int err = SSL_get_error(server->ssl[i], r);

                                if (err == SSL_ERROR_WANT_READ) return 0;


                                if (err == SSL_ERROR_WANT_WRITE) return 15;


            			if (err == SSL_ERROR_ZERO_RETURN) {
                			return -1;
            			}

            			return -1;
        		}
                        case READ_USERNAME_LEN_SER:
                        {
                                ssize_t t = SSL_read(server->ssl[i] , (unsigned char *)&pack->header.len + server->client[i].income, sizeof(pack->header.len) - server->client[i].income);

                                if(t > 0) {
                                        server->fds[i].events = POLLIN;
                                        server->client[i].income += t;
                                        if (server->client[i].income < sizeof(pack->header.len)) {
                                                continue;
                                        }
					if(server->client[i].income == sizeof(pack->header.len)) {
                                                server->client[i].income = 0;
						server->client[i].state = READ_USERNAME_SER;
						continue;
					}

                                                return -1;

                                }


                                int err = SSL_get_error(server->ssl[i], t);

                                if (err == SSL_ERROR_WANT_READ) return 0;


                                if (err == SSL_ERROR_WANT_WRITE) return 15;

                                return -1;
                        }
			case READ_USERNAME_SER:
			{
				ssize_t d = SSL_read(server->ssl[i] , pack->sender + server->client[i].income , pack->header.len - server->client[i].income);

				if(d > 0) {
					server->fds[i].events = POLLIN;
					server->client[i].income += d;

					if(server->client[i].income == pack->header.len) {
					server->client[i].income = 0;
					server->client[i].state = READ_SIZE_SER;
					}
				continue;
				}
			int err = SSL_get_error(server->ssl[i] , d);

			if(err == SSL_ERROR_WANT_READ) return 0;

			if(err == SSL_ERROR_WANT_WRITE) return 15;

			return -1;

			}
			case READ_SIZE_SER:
			{
                                ssize_t t = SSL_read(server->ssl[i] , (unsigned char *)&pack->header.size + server->client[i].income, sizeof(pack->header.size) - server->client[i].income);

                                if(t > 0) {
					server->fds[i].events = POLLIN;
                                        server->client[i].income += t;
					if (server->client[i].income < sizeof(pack->header.size)) {
            					continue;
        				}

                                        	pack->header.size = ntohl(pack->header.size);
						server->client[i].income = 0;


					if(pack->header.state == SEND_MESSAGE) {
        	                                if(pack->header.size > sizeof(pack->buffer)) {
	                                                return -1;
                	                        }

						server->client[i].state = READ_PAYLOAD_SER;
						continue;
					}

					if(pack->header.state == SEND_DATA) {
						return 29;
					}

					if(pack->header.state == EXIT) {
						return 35;
					}


						return -1;

				}


            			int err = SSL_get_error(server->ssl[i], t);

            			if (err == SSL_ERROR_WANT_READ) return 0;


				if (err == SSL_ERROR_WANT_WRITE) return 15;

            			return -1;
			}
			case READ_PAYLOAD_SER:
			{
                                ssize_t g = SSL_read(server->ssl[i] , (unsigned char *)pack->buffer + server->client[i].income, pack->header.size - server->client[i].income);

				if(g > 0) {
					server->fds[i].events = POLLIN;
					server->client[i].income += g;

			                if (server->client[i].income == pack->header.size) {
                    				server->client[i].income = 0;
                    				server->client[i].state = READ_STATE_SER;
                    				return 1;
                			}
					continue;
				}
			        int err = SSL_get_error(server->ssl[i], g);

            			if (err == SSL_ERROR_WANT_READ) return 0;


				if (err == SSL_ERROR_WANT_WRITE) return 15;

            			return -1;
			}
		}
	}

	return 1;
}


void server_stop(server_information *server) {

  for (int i = 1; i < server->nfds; i++) {
    SSL_shutdown(server->ssl[i]);
    SSL_free(server->ssl[i]);
    close(server->fds[i].fd);
  }

  free(server->onion_address);
  close(server->server_socket);
  SSL_CTX_free(server->ctx);
}

void server_start(server_information *server, packet *pack) {

  int status;

  while (1) {

    int ret = poll(server->fds, server->nfds, -1);

    if (ret == -1) {
      perror("poll");
      break;
    }

    for (int i = 0; i < server->nfds; i++) {
      if (i == 0) {
        if (server->fds[i].revents & POLLIN) {
          printf("Incoming connection\n");
          int client = accept(server->server_socket, 0, 0);
          if (client < 0) {
            perror("accept");
            continue;
          }

          if (server->nfds >= 5) {
            close(client);
            fprintf(stderr, "Too many clients\n");
            continue;
          }

          if (client > 0) {
            server->fds[server->nfds].fd = client;
            server->fds[server->nfds].events = POLLIN;
            server->ssl[server->nfds] = SSL_new(server->ctx);
	    server->client[server->nfds].state = READ_STATE_SER;
	    server->client[server->nfds].income = 0;

	    if (!server->ssl[server->nfds]) {
              ERR_print_errors_fp(stderr);
              close(client);
              continue;
            }

            server->fds[server->nfds].revents = 0;

            if (SSL_set_fd(server->ssl[server->nfds], client) != 1) {
              ERR_print_errors_fp(stderr);
              SSL_free(server->ssl[server->nfds]);
              close(client);
              continue;
            }

            SSL_set_accept_state(server->ssl[server->nfds]);
            server->nfds++;
            printf("SSL object created, waiting for TLS handshake\n");
          }
        }
      } else {

        if (server->fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
          SSL_free(server->ssl[i]);
          close(server->fds[i].fd);
          server->fds[i] = server->fds[server->nfds - 1];
          server->ssl[i] = server->ssl[server->nfds - 1];
	  server->client[i] = server->client[server->nfds - 1];
          server->nfds--;
          i--;
          continue;
        }

        if (server->fds[i].revents & (POLLIN | POLLOUT)) {
          if (!SSL_is_init_finished(server->ssl[i])) {
            printf("Calling SSL_accept() for client %d\n", i);
            int err = SSL_accept(server->ssl[i]);
            if (err <= 0) {
              int ssl_err = SSL_get_error(server->ssl[i], err);
              fprintf(stderr, "SSL_accept failed: ret=%d ssl_err=%d\n", ret,
                      ssl_err);
              ERR_print_errors_fp(stderr);
              if (ssl_err == SSL_ERROR_WANT_READ)
                continue;
              if (ssl_err == SSL_ERROR_WANT_WRITE) {
                server->fds[i].events |= POLLOUT;
                continue;
              }

              SSL_free(server->ssl[i]);
              close(server->fds[i].fd);
              server->fds[i] = server->fds[server->nfds - 1];
              server->ssl[i] = server->ssl[server->nfds - 1];
	      server->client[i] = server->client[server->nfds - 1];
              server->nfds--;
              i--;
              continue;
            }

            server->fds[i].events = POLLIN;
            printf("TLS handshake completed for client %d\n", i);
            continue;
          }

          printf("connected\n");
printf("SERVER: before recv_packet\n");
          status = recv_packet(pack , server , i);
printf("SERVER: recv_packet -> %d\n", status);
	  if (status == 0) {
	   server->fds[i].events = POLLIN;
    	   continue;
	  }

	  if(status == 15) {
	   server->fds[i].events = POLLOUT;
	   continue;
	  }

          if (status == 1) {
            printf("number of bytes we've got from client: %d\n",pack->header.size);
                        printf("%.*s\n", (int)pack->header.size, pack->buffer);
          }
          if (status == 35) {
            printf("client requested exit\n");
            pack->header.state = EXIT;
            pack->header.size = 0;
            send_packet(pack, server , i);
            SSL_shutdown(server->ssl[i]);
            SSL_free(server->ssl[i]);
            close(server->fds[i].fd);
            server->fds[i] = server->fds[server->nfds - 1];
            server->ssl[i] = server->ssl[server->nfds - 1];
	    server->client[i] = server->client[server->nfds - 1];
            server->nfds--;
            i--;
            continue;
          }

          if (status < 0) {
            SSL_shutdown(server->ssl[i]);
            SSL_free(server->ssl[i]);
            close(server->fds[i].fd);
            server->fds[i] = server->fds[server->nfds - 1];
            server->ssl[i] = server->ssl[server->nfds - 1];
	    server->client[i] = server->client[server->nfds - 1];
            server->nfds--;
            i--;
            continue;
          }

          pack->header.state = SEND_MESSAGE;

	printf("Broadcasting packet to %d clients\n",server->nfds - 1);

	for (int j = 1; j < server->nfds; j++) {

	    if(i == j) {
		continue;
	        }

    	    printf("Sending packet to client %d\n", j);

    	    if (send_packet(pack , server , j) != 1) {
        	fprintf(stderr,"Failed to send to client %d\n",j);
    		}


	    }

        }
      }
    }
}

server_stop(server);
}

