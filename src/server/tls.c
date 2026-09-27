#include "../include/tls.h"

SSL_CTX *create_context() {

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	if(!ctx) {
        	ERR_print_errors_fp(stderr);
		return NULL;
	}

	if(SSL_CTX_use_certificate_file(ctx , "server.crt", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return NULL;
	}

        if(SSL_CTX_use_PrivateKey_file(ctx , "server.key", SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                return NULL;
        }

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		SSL_CTX_free(ctx);
		return NULL;
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);


	return ctx;
}
