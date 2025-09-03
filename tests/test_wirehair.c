#include <string.h>

#include "unity.h"
#include "wirehair.h"

#define PACKET_SIZE 128
#define MESSAGE_SIZE 1024

static WirehairCodec encoder;
static WirehairCodec decoder;
static uint8_t message[MESSAGE_SIZE];
static uint8_t recovered[MESSAGE_SIZE];

void setUp(void) {
    // Initialize message with known pattern
    for (int i = 0; i < MESSAGE_SIZE; ++i)
        message[i] = (uint8_t)(i & 0xFF);

    TEST_ASSERT_EQUAL(Wirehair_Success, wirehair_init());

    encoder = wirehair_encoder_create(NULL, message, MESSAGE_SIZE, PACKET_SIZE);
    TEST_ASSERT_NOT_NULL(encoder);

    decoder = wirehair_decoder_create(NULL, MESSAGE_SIZE, PACKET_SIZE);
    TEST_ASSERT_NOT_NULL(decoder);
}

void tearDown(void) {
    wirehair_free(encoder);
    wirehair_free(decoder);
}

void test_encode_decode_full_sequence(void) {
    uint32_t block_id = 0;
    WirehairResult result;

    for (;;) {
        block_id++;
        uint8_t block[PACKET_SIZE];
        uint32_t write_len = 0;

        result =
            wirehair_encode(encoder, block_id, block, PACKET_SIZE, &write_len);
        TEST_ASSERT_EQUAL_UINT(Wirehair_Success, result);

        result = wirehair_decode(decoder, block_id, block, write_len);
        if (result == Wirehair_Success)
            break;
        TEST_ASSERT_EQUAL(Wirehair_NeedMore, result);
    }

    TEST_ASSERT_EQUAL(Wirehair_Success,
                      wirehair_recover(decoder, recovered, MESSAGE_SIZE));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(message, recovered, MESSAGE_SIZE);
}

void test_simulated_packet_loss(void) {
    uint32_t block_id = 0;
    uint32_t sent = 0;
    WirehairResult result;

    while (sent < (MESSAGE_SIZE / PACKET_SIZE) + 4) {
        block_id++;
        uint8_t block[PACKET_SIZE];
        uint32_t write_len = 0;

        result =
            wirehair_encode(encoder, block_id, block, PACKET_SIZE, &write_len);
        TEST_ASSERT_EQUAL(Wirehair_Success, result);

        if (block_id % 5 == 0)
            // Simulate 20% packet loss
            continue;

        sent++;
        result = wirehair_decode(decoder, block_id, block, write_len);
        if (result == Wirehair_Success)
            break;
        TEST_ASSERT_EQUAL(Wirehair_NeedMore, result);
    }

    TEST_ASSERT_EQUAL(Wirehair_Success,
                      wirehair_recover(decoder, recovered, MESSAGE_SIZE));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(message, recovered, MESSAGE_SIZE);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_encode_decode_full_sequence);
    RUN_TEST(test_simulated_packet_loss);
    return UNITY_END();
}
