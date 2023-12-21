#include "tlv.h"
#include "constants.h"
#ifndef TEST
#include "os.h"
#endif

bool tlv_read_next(buffer_t *buffer, tlv_t *tlv) {
    LEDGER_ASSERT(buffer != NULL, "Null buffer\n");
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");

    if (!buffer_can_read(buffer, 2)) {
        PRINTF("Cannot read TLV header\n");
        return false;
    }

    buffer_read_u8(buffer, &tlv->type);
    buffer_read_u8(buffer, &tlv->length);

    if (!buffer_can_read(buffer, tlv->length)) {
        PRINTF("Cannot read TLV value\n");
        return false;
    }
    tlv->value = buffer->ptr + buffer->offset;
    buffer_seek_cur(buffer, tlv->length);
    return true;
}

bool tlv_read_varint_u8(tlv_t *tlv, uint8_t *out) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_VARINT || tlv->length != 1) {
        return false;
    }
    *out = tlv->value[0];
    return true;
}

bool tlv_read_varint_u16(tlv_t *tlv, uint16_t *out) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_VARINT || tlv->length != sizeof(uint16_t)) {
        return false;
    }
    buffer_t buffer = {.ptr = tlv->value, .size = tlv->length, .offset = 0};
    return buffer_read_u16(&buffer, out, BE);
}

bool tlv_read_varint_u32(tlv_t *tlv, uint32_t *out) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_VARINT || tlv->length != sizeof(uint32_t)) {
        return false;
    }
    buffer_t buffer = {.ptr = tlv->value, .size = tlv->length, .offset = 0};
    return buffer_read_u32(&buffer, out, BE);
}

bool tlv_read_hash(tlv_t *tlv, uint8_t *out) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_HASH || tlv->length > HASH_LEN) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_pubkey(tlv_t *tlv, uint8_t *out) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_PUBKEY || tlv->length > MEMBER_KEY_LEN) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_bytes(tlv_t *tlv, uint8_t *out, size_t out_size) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_BYTES || tlv->length > out_size) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_string(tlv_t *tlv, char *out, size_t out_size) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_STRING || tlv->length >= out_size) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    out[tlv->length] = '\0';
    return true;
}

bool tlv_read_signature(tlv_t *tlv, uint8_t *out, size_t out_size) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_SIG || tlv->length > out_size) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}