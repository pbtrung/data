#include <stdio.h>

#include <apr_general.h>
#include <apr_pools.h>

#include "nntp.h"

int main() {
    apr_initialize();

    apr_pool_t *pool;
    apr_pool_create(&pool, NULL);

    nntp_client_t client;
    memset(&client, 0, sizeof(client));

    printf("Testing plain connection...\n");
    if (nntp_connect(&client, pool, "news.eternal-september.org", 119, 0) ==
        0) {
        printf("Successfully connected!\n");
        nntp_close(&client);
    } else {
        printf("Failed to connect\n");
    }

    printf("Testing SSL connection...\n");
    if (nntp_connect(&client, pool, "news.eternal-september.org", 563, 1) ==
        0) {
        printf("Successfully connected with SSL!\n");
        nntp_close(&client);
    } else {
        printf("Failed to connect with SSL\n");
    }

    apr_pool_destroy(pool);
    apr_terminate();
    return 0;
}
