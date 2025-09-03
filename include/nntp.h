#ifndef NNTP_H
#define NNTP_H

#include <openssl/ssl.h>

typedef struct {
    int sock;
    char *host;
    int port;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
} nntp_client_t;

int nntp_connect_ssl(nntp_client_t *c, const char *host, int port);
int nntp_auth(nntp_client_t *c, const char *user, const char *pass);
char *nntp_get(nntp_client_t *c, const char *id);
int nntp_post(nntp_client_t *c, const char *id, const char *body);
void nntp_close(nntp_client_t *c);

#endif