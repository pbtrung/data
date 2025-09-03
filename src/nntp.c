#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "nntp.h"

static int ssl_initialized = 0;

static void init_ssl() {
    if (!ssl_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialized = 1;
    }
}

static int send_line(nntp_client_t *c, const char *line) {
    char buf[1024];
    int ret;
    if (strlen(line) > sizeof(buf) - 3)
        return -1;
    snprintf(buf, sizeof(buf), "%s\r\n", line);

    if (c->ssl) {
        ret = SSL_write(c->ssl, buf, strlen(buf));
        return (ret > 0) ? ret : -1;
    } else {
        ret = send(c->sock, buf, strlen(buf), 0);
        return (ret > 0) ? ret : -1;
    }
}

static int recv_line(nntp_client_t *c, char *buf, size_t sz) {
    int i = 0;
    char ch;

    while (i < sz - 1) {
        int n;
        if (c->ssl) {
            n = SSL_read(c->ssl, &ch, 1);
            if (n <= 0) {
                int ssl_error = SSL_get_error(c->ssl, n);
                if (ssl_error == SSL_ERROR_WANT_READ ||
                    ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue; // Try again
                }
                break;
            }
        } else {
            n = recv(c->sock, &ch, 1, 0);
            if (n <= 0)
                break;
        }

        buf[i++] = ch;
        if (ch == '\n')
            break;
    }
    buf[i] = '\0';
    return i;
}

static int create_socket_and_connect(const char *host, int port) {
    int sock;
    struct sockaddr_in server_addr;
    struct hostent *host_entry;
    struct timeval timeout;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    // Set socket timeout (10 seconds)
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
            0 ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) <
            0) {
        close(sock);
        return -1;
    }

    // Resolve hostname
    host_entry = gethostbyname(host);
    if (!host_entry) {
        close(sock);
        return -1;
    }

    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0],
           host_entry->h_length);

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
        close(sock);
        return -1;
    }

    return sock;
}

// Direct SSL NNTP connection (implicit SSL)
int nntp_connect_ssl(nntp_client_t *c, const char *host, int port) {
    char buf[512];

    if (!c || !host)
        return -1;

    init_ssl();

    // Initialize client structure
    memset(c, 0, sizeof(nntp_client_t));
    c->host = strdup(host);
    c->port = port;
    c->ssl = NULL;
    c->ssl_ctx = NULL;

    c->sock = create_socket_and_connect(host, port);
    if (c->sock < 0) {
        free(c->host);
        return -1;
    }

    c->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ssl_ctx) {
        close(c->sock);
        free(c->host);
        return -1;
    }

    // Configure SSL context
    SSL_CTX_set_options(c->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_NONE, NULL);

    c->ssl = SSL_new(c->ssl_ctx);
    if (!c->ssl) {
        SSL_CTX_free(c->ssl_ctx);
        close(c->sock);
        free(c->host);
        return -1;
    }

    SSL_set_fd(c->ssl, c->sock);

    int ssl_ret = SSL_connect(c->ssl);
    if (ssl_ret <= 0) {
        SSL_free(c->ssl);
        SSL_CTX_free(c->ssl_ctx);
        close(c->sock);
        free(c->host);
        return -1;
    }

    if (recv_line(c, buf, sizeof(buf)) <= 0) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        SSL_CTX_free(c->ssl_ctx);
        close(c->sock);
        free(c->host);
        return -1;
    }

    if (strncmp(buf, "200", 3) != 0 && strncmp(buf, "201", 3) != 0) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        SSL_CTX_free(c->ssl_ctx);
        close(c->sock);
        free(c->host);
        return -1;
    }

    return 0;
}

int nntp_auth(nntp_client_t *c, const char *user, const char *pass) {
    char buf[512], line[512];
    if (!c || !user || !pass)
        return -1;

    snprintf(line, sizeof(line), "AUTHINFO USER %s", user);
    if (send_line(c, line) < 0)
        return -1;
    if (recv_line(c, buf, sizeof(buf)) <= 0)
        return -1;
    if (strncmp(buf, "381", 3) != 0)
        return -1;

    snprintf(line, sizeof(line), "AUTHINFO PASS %s", pass);
    if (send_line(c, line) < 0)
        return -1;
    if (recv_line(c, buf, sizeof(buf)) <= 0)
        return -1;
    if (strncmp(buf, "281", 3) != 0)
        return -1;

    return 0;
}

char *nntp_get(nntp_client_t *c, const char *id) {
    char buf[512];
    char line[1024];
    size_t len = 4096, pos = 0;
    char *out;

    if (!c || !id)
        return NULL;

    snprintf(line, sizeof(line), "ARTICLE %s", id);
    if (send_line(c, line) < 0)
        return NULL;
    if (recv_line(c, buf, sizeof(buf)) <= 0)
        return NULL;
    if (strncmp(buf, "220", 3) != 0)
        return NULL;

    out = malloc(len);
    if (!out)
        return NULL;

    memset(out, 0, len);

    while (recv_line(c, buf, sizeof(buf)) > 0) {
        if (strcmp(buf, ".\r\n") == 0 || strcmp(buf, ".\n") == 0)
            break;

        size_t buf_len = strlen(buf);
        if (pos + buf_len >= len - 1) {
            len *= 2;
            char *new_out = realloc(out, len);
            if (!new_out) {
                free(out);
                return NULL;
            }
            out = new_out;
            memset(out + pos, 0, len - pos); // Clear new memory
        }
        strcpy(out + pos, buf);
        pos += buf_len;
    }
    return out;
}

int nntp_post(nntp_client_t *c, const char *id, const char *body) {
    char buf[512];
    if (!c || !body)
        return -1;

    if (send_line(c, "POST") < 0)
        return -1;
    if (recv_line(c, buf, sizeof(buf)) <= 0)
        return -1;
    if (strncmp(buf, "340", 3) != 0)
        return -1;

    if (send_line(c, body) < 0)
        return -1;
    if (send_line(c, ".") < 0)
        return -1;

    if (recv_line(c, buf, sizeof(buf)) <= 0)
        return -1;
    if (strncmp(buf, "240", 3) != 0)
        return -1;

    return 0;
}

void nntp_close(nntp_client_t *c) {
    if (!c)
        return;

    send_line(c, "QUIT");

    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
        c->ssl_ctx = NULL;
    }
    if (c->sock >= 0) {
        close(c->sock);
        c->sock = -1;
    }
    if (c->host) {
        free(c->host);
        c->host = NULL;
    }
}