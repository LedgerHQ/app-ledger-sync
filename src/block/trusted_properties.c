#include "trusted_properties.h"
#include "../crypto.h"
#include <string.h>
#include "../globals.h"
#include "ledger_assert.h"

// Format is [NONCE][DATA][CHECKSUM]

int serialize_trusted_member(stream_trusted_member_t *member, uint8_t *buffer, size_t buffer_size) {
    uint8_t hash[32];

    if (buffer_size < TP_BUFFER_SIZE_NEW_MEMBER) {
        return TP_BUFFER_OVERFLOW;
    }
    cx_trng_get_random_data(buffer, TP_NONCE_SIZE);
    LEDGER_ASSERT(buffer != NULL, "Null buffer");

    memcpy(buffer + TP_NONCE_SIZE, member, sizeof(stream_trusted_member_t));
    crypto_digest(buffer, TP_NONCE_SIZE + sizeof(stream_trusted_member_t), hash, sizeof(hash));
    memcpy(buffer + TP_NONCE_SIZE + sizeof(stream_trusted_member_t), hash, TP_CHECKSUM_LEN);
    return TP_SUCCESS;
}

int deserialize_trusted_member(uint8_t *buffer, size_t buffer_size, stream_trusted_member_t *out) {
    uint8_t hash[32];

    LEDGER_ASSERT(buffer != NULL, "Null buffer");
    LEDGER_ASSERT(out != NULL, "Null out buffer");

    if (buffer_size < TP_BUFFER_SIZE_NEW_MEMBER) {
        return TP_BUFFER_OVERFLOW;
    }

    crypto_digest(buffer, TP_NONCE_SIZE + sizeof(stream_trusted_member_t), hash, sizeof(hash));

    if (memcmp(hash, buffer + TP_NONCE_SIZE + sizeof(stream_trusted_member_t), TP_CHECKSUM_LEN) !=
        0) {
        return TP_INVALID_CHECKSUM;
    }

    memcpy(out, buffer + TP_NONCE_SIZE, sizeof(stream_trusted_member_t));

    return TP_SUCCESS;
}