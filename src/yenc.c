#include <stdio.h>
#include <string.h>

#include "yenc.h"

static inline int needs_escape(uint8_t c) {
    return (c == 0x00 || c == 0x0A || c == 0x0D || c == 0x3D);
}

data_status_t yenc_encode(const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len, size_t wrap) {
    if (!in || !out || wrap == 0)
        return ERR_yenc_encode;

    *out_len = 0;
    size_t line_len = 0;
    *out_len += sprintf((char *)out + *out_len, "=ybegin line=%zu\r\n", wrap);

    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)((in[i] + 42) & 0xFF);
        if (needs_escape(c)) {
            out[(*out_len)++] = '=';
            out[(*out_len)++] = (uint8_t)((c + 64) & 0xFF);
            line_len += 2;
        } else {
            out[(*out_len)++] = c;
            line_len++;
        }
        if (line_len >= wrap) {
            out[(*out_len)++] = '\r';
            out[(*out_len)++] = '\n';
            line_len = 0;
        }
    }

    if (line_len > 0) {
        out[(*out_len)++] = '\r';
        out[(*out_len)++] = '\n';
    }

    *out_len += sprintf((char *)out + *out_len, "=yend\r\n");
    return DATA_SUCCESS;
}

data_status_t yenc_decode(const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len) {
    if (!in || !out || len == 0)
        return ERR_yenc_decode;

    *out_len = 0;
    size_t i = 0;
    if (len >= 7 && memcmp(in, "=ybegin", 7) == 0) {
        while (i < len) {
            if (in[i] == '\n') {
                i++;
                break;
            }
            if (in[i] == '\r' && i + 1 < len && in[i + 1] == '\n') {
                i += 2;
                break;
            }
            i++;
        }
    }

    while (i < len) {
        uint8_t c = in[i++];
        if (c == '=' && i + 3 < len && memcmp(in + i - 1, "=yend", 5) == 0)
            break;
        if (c == '\r' || c == '\n')
            continue;
        if (c == '=') {
            if (i < len) {
                uint8_t esc = (uint8_t)((in[i++] - 64) & 0xFF);
                out[(*out_len)++] = (uint8_t)((esc - 42) & 0xFF);
            }
        } else {
            out[(*out_len)++] = (uint8_t)((c - 42) & 0xFF);
        }
    }
    return DATA_SUCCESS;
}
