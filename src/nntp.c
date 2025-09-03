#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <apr_portable.h>
#include <apr_strings.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "nntp.h"

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
        apr_size_t len = strlen(buf);
        return (apr_socket_send(c->sock, buf, &len) == APR_SUCCESS) ? (int)len
                                                                    : -1;
    }
}

static int recv_line(nntp_client_t *c, char *buf, size_t sz) {
    int i = 0;
    char ch;
    while (i < sz - 1) {
        int n;
        if (c->ssl)
            n = SSL_read(c->ssl, &ch, 1);
        else {
            apr_size_t s = 1;
            apr_status_t st = apr_socket_recv(c->sock, &ch, &s);
            if (st != APR_SUCCESS || s == 0)
                break;
            n = s;
        }
        if (n <= 0)
            break;
        buf[i++] = ch;
        if (ch == '\n')
            break;
    }
    buf[i] = '\0';
    return i;
}

int nntp_connect(nntp_client_t *c, apr_pool_t *parent_pool, const char *host,
                 int port, int starttls) {
    apr_status_t status;
    apr_sockaddr_t *sa;
    char buf[512];
    if (!c || !parent_pool || !host)
        return -1;

    if (apr_pool_create(&c->pool, parent_pool) != APR_SUCCESS)
        return -1;

    c->host = apr_pstrdup(c->pool, host);
    c->port = port;
    c->ssl = NULL;
    c->ssl_ctx = NULL;
    c->sock = NULL;

    if (starttls) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }

    status = apr_sockaddr_info_get(&sa, host, APR_INET, port, 0, c->pool);
    if (status != APR_SUCCESS)
        return -1;

    status = apr_socket_create(&c->sock, sa->family, SOCK_STREAM, APR_PROTO_TCP,
                               c->pool);
    if (status != APR_SUCCESS)
        return -1;

    status = apr_socket_connect(c->sock, sa);
    if (status != APR_SUCCESS) {
        apr_socket_close(c->sock);
        c->sock = NULL;
        return -1;
    }

    if (recv_line(c, buf, sizeof(buf)) <= 0) {
        apr_socket_close(c->sock);
        c->sock = NULL;
        return -1;
    }
    if (strncmp(buf, "200", 3) != 0 && strncmp(buf, "201", 3) != 0) {
        apr_socket_close(c->sock);
        c->sock = NULL;
        return -1;
    }

    if (starttls) {
        if (send_line(c, "STARTTLS") < 0)
            return -1;
        if (recv_line(c, buf, sizeof(buf)) <= 0)
            return -1;
        if (strncmp(buf, "382", 3) != 0)
            return -1;

        c->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!c->ssl_ctx)
            return -1;

        c->ssl = SSL_new(c->ssl_ctx);
        if (!c->ssl) {
            SSL_CTX_free(c->ssl_ctx);
            c->ssl_ctx = NULL;
            return -1;
        }

        apr_os_sock_t os_sock;
        if (apr_os_sock_get(&os_sock, c->sock) != APR_SUCCESS) {
            SSL_free(c->ssl);
            SSL_CTX_free(c->ssl_ctx);
            c->ssl = NULL;
            c->ssl_ctx = NULL;
            return -1;
        }

        SSL_set_fd(c->ssl, os_sock);
        if (SSL_connect(c->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(c->ssl);
            SSL_CTX_free(c->ssl_ctx);
            c->ssl = NULL;
            c->ssl_ctx = NULL;
            return -1;
        }
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
    apr_pool_t *subpool;
    apr_size_t len = 4096, pos = 0;
    char *out;
    if (!c || !id)
        return NULL;
    if (send_line(c, apr_psprintf(c->pool, "ARTICLE %s", id)) < 0)
        return NULL;
    if (recv_line(c, buf, sizeof(buf)) <= 0)
        return NULL;
    if (strncmp(buf, "220", 3) != 0)
        return NULL;

    apr_pool_create(&subpool, c->pool);
    out = apr_pcalloc(subpool, len);
    if (!out)
        return NULL;

    while (recv_line(c, buf, sizeof(buf)) > 0) {
        if (strcmp(buf, ".\r\n") == 0 || strcmp(buf, ".\n") == 0)
            break;
        size_t buf_len = strlen(buf);
        if (pos + buf_len >= len - 1) {
            len *= 2;
            char *new_out = apr_pcalloc(subpool, len);
            if (!new_out)
                break;
            memcpy(new_out, out, pos);
            out = new_out;
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
    if (c->sock) {
        apr_socket_close(c->sock);
        c->sock = NULL;
    }
    if (c->pool) {
        apr_pool_destroy(c->pool);
        c->pool = NULL;
    }
}
