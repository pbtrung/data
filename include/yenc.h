#ifndef YENC_H
#define YENC_H

#include <stddef.h>
#include <stdint.h>

#include "err.h"

data_status_t yenc_encode(const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len, size_t wrap);
data_status_t yenc_decode(const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len);

#endif // YENC_H
