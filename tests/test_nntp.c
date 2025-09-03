#include <stdio.h>

#include "nntp.h"

int main() {
    nntp_client_t client;
    memset(&client, 0, sizeof(client));

    printf("Testing SSL connection\n");
    if (nntp_connect_ssl(&client, "", 563) == 0) {
        printf("Successfully connected with SSL!\n");
        int rv = nntp_auth(&client, "", "");
        if (rv == 0)
            printf("Successfully authenticated!\n");
        else
            printf("Failed to authenticate\n");
        nntp_close(&client);
    } else {
        printf("Failed to connect with SSL\n");
    }

    return 0;
}
