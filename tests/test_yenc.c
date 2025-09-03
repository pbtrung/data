#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "unity.h"
#include "yenc.h"

#define WRAP_COLS 128

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

// helper for round-trip check
static void check_roundtrip(const char *label, const uint8_t *data, size_t len,
                            size_t wrap) {
    size_t enc_size = len * 3 + 256;
    uint8_t *enc = malloc(enc_size);
    uint8_t *dec = malloc(len + 16);
    TEST_ASSERT_NOT_NULL(enc);
    TEST_ASSERT_NOT_NULL(dec);

    size_t enc_len;
    data_status_t rv = yenc_encode(data, len, enc, &enc_len, wrap);
    TEST_ASSERT_EQUAL_INT(rv, DATA_SUCCESS);
    size_t dec_len;
    rv = yenc_decode(enc, enc_len, dec, &dec_len);
    TEST_ASSERT_EQUAL_INT(rv, DATA_SUCCESS);

    TEST_ASSERT_EQUAL_size_t(len, dec_len);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(data, dec, len, label);

    free(enc);
    free(dec);
}

void test_simple_text(void) {
    const char *msg = "Hello yEnc!";
    check_roundtrip("Simple text", (const uint8_t *)msg, strlen(msg),
                    WRAP_COLS);
}

void test_control_chars(void) {
    const uint8_t msg[] = {'A', '=', '\r', '\n', 0x00, 0xFF};
    check_roundtrip("Control chars", msg, sizeof(msg), WRAP_COLS);
}

void test_all_bytes(void) {
    uint8_t msg[256];
    for (int i = 0; i < 256; i++)
        msg[i] = (uint8_t)i;
    check_roundtrip("All bytes", msg, sizeof(msg), WRAP_COLS);
}

void test_single_escape(void) {
    uint8_t vals[] = {0x00, 0x0A, 0x0D, 0x3D};
    for (size_t i = 0; i < sizeof(vals); i++)
        check_roundtrip("Single escape", &vals[i], 1, WRAP_COLS);
}

void test_tricky(void) {
    uint8_t tricky[] = {214, 224, 227, 251};
    check_roundtrip("Tricky", tricky, sizeof(tricky), WRAP_COLS);
}

void test_line_boundary(void) {
    uint8_t buf[WRAP_COLS];
    memset(buf, 'A', sizeof(buf));
    check_roundtrip("Line boundary", buf, sizeof(buf), WRAP_COLS);
}

void test_no_escapes(void) {
    const char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    check_roundtrip("No escapes", (const uint8_t *)msg, strlen(msg), WRAP_COLS);
}

void test_fuzz_random(void) {
    srand((unsigned)time(NULL));
    for (int t = 0; t < 10; t++) {
        size_t len = rand() % 1024 + 1;
        uint8_t *buf = malloc(len);
        TEST_ASSERT_NOT_NULL(buf);
        for (size_t i = 0; i < len; i++)
            buf[i] = rand() % 256;
        check_roundtrip("Fuzz", buf, len, WRAP_COLS);
        free(buf);
    }
}

void test_wrap_lengths(void) {
    const char *msg = "This is a test string for wrap length check.";
    size_t wrap_lengths[] = {10, 32, 64, 128, 256};
    for (size_t i = 0; i < sizeof(wrap_lengths) / sizeof(wrap_lengths[0]);
         i++) {
        check_roundtrip("Wrap", (const uint8_t *)msg, strlen(msg),
                        wrap_lengths[i]);
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_simple_text);
    RUN_TEST(test_control_chars);
    RUN_TEST(test_all_bytes);
    RUN_TEST(test_single_escape);
    RUN_TEST(test_tricky);
    RUN_TEST(test_line_boundary);
    RUN_TEST(test_no_escapes);
    RUN_TEST(test_fuzz_random);
    RUN_TEST(test_wrap_lengths);
    return UNITY_END();
}
