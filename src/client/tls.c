#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX *create_client_context() {

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
		ERR_print_errors_fp(stderr);
        	SSL_CTX_free(ctx);
        	return NULL;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	return ctx;
}
