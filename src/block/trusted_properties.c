#include "trusted_properties.h"
#include "../crypto.h"
#include <string.h>
#include "../globals.h"

// Format is [GENERATION][DATA][CHECKSUM]

/* A PUBLISH_KEY response carries both TP_XPRIV and TP_NEW_MEMBER, and AES-GCM forbids reusing
 * an IV under a given key. TP_NEW_MEMBER is opaque to the host, which only echoes it back to
 * SET_TRUSTED_MEMBER, so deriving its IV keeps the response layout unchanged. */
#define TRUSTED_MEMBER_IV_MASK 0x5A

void derive_trusted_member_iv(const uint8_t *response_iv, uint8_t *member_iv) {
    LEDGER_ASSERT(response_iv != NULL, "Null response_iv");
    LEDGER_ASSERT(member_iv != NULL, "Null member_iv");

    for (size_t i = 0; i < IV_LEN; i++) {
        member_iv[i] = response_iv[i] ^ TRUSTED_MEMBER_IV_MASK;
    }
}

int serialize_trusted_member(stream_trusted_member_t *member,
                             uint32_t generation,
                             uint8_t *buffer,
                             size_t buffer_size) {
    uint8_t hash[32];

    if (buffer_size < TP_BUFFER_SIZE_NEW_MEMBER) {
        return TP_BUFFER_OVERFLOW;
    }
    LEDGER_ASSERT(buffer != NULL, "Null buffer");

    memcpy(buffer, &generation, TP_GENERATION_SIZE);
    memcpy(buffer + TP_GENERATION_SIZE, member, sizeof(stream_trusted_member_t));
    crypto_digest(buffer, TP_GENERATION_SIZE + sizeof(stream_trusted_member_t), hash, sizeof(hash));
    memcpy(buffer + TP_GENERATION_SIZE + sizeof(stream_trusted_member_t), hash, TP_CHECKSUM_LEN);
    return TP_GENERATION_SIZE + sizeof(stream_trusted_member_t) + TP_CHECKSUM_LEN;
}

int deserialize_trusted_member(uint8_t *buffer,
                               size_t buffer_size,
                               uint32_t generation,
                               stream_trusted_member_t *out) {
    uint8_t hash[32];

    LEDGER_ASSERT(buffer != NULL, "Null buffer");
    LEDGER_ASSERT(out != NULL, "Null out buffer");

    if (buffer_size < TP_BUFFER_SIZE_NEW_MEMBER) {
        return TP_BUFFER_OVERFLOW;
    }

    crypto_digest(buffer, TP_GENERATION_SIZE + sizeof(stream_trusted_member_t), hash, sizeof(hash));

    if (memcmp(hash,
               buffer + TP_GENERATION_SIZE + sizeof(stream_trusted_member_t),
               TP_CHECKSUM_LEN) != 0) {
        return TP_INVALID_CHECKSUM;
    }
    // A member issued before a block was dropped may come from that unsigned block
    if (memcmp(buffer, &generation, TP_GENERATION_SIZE) != 0) {
        return TP_STALE_GENERATION;
    }

    memcpy(out, buffer + TP_GENERATION_SIZE, sizeof(stream_trusted_member_t));

    return TP_SUCCESS;
}
