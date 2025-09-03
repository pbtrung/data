#ifndef NNTP_H
#define NNTP_H

#include <apr_network_io.h>
#include <openssl/ssl.h>

typedef struct nntp_client_t {
    apr_pool_t *pool;
    char *host;
    int port;
    apr_socket_t *sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
} nntp_client_t;

int nntp_connect(nntp_client_t *client, apr_pool_t *parent_pool,
                 const char *host, int port, int starttls);
int nntp_auth(nntp_client_t *client, const char *user, const char *pass);
char *nntp_get(nntp_client_t *client, const char *article_id);
int nntp_post(nntp_client_t *client, const char *article_id, const char *body);
void nntp_close(nntp_client_t *client);

#endif
