#pragma once

#include "buffer.h"

#ifndef TEST
#include "ledger_assert.h"
#else
#include <assert.h>
#define LEDGER_ASSERT(x, y) assert(x)
#endif

typedef enum {
    // General purpose types
    TLV_TYPE_NULL = 0x00,
    TLV_TYPE_VARINT = 0x01,
    TLV_TYPE_HASH = 0x02,
    TLV_TYPE_SIG = 0x03,
    TLV_TYPE_STRING = 0x04,
    TLV_TYPE_BYTES = 0x05,
    TLV_TYPE_PUBKEY = 0x06,

    // Command types
    TLV_TYPE_CREATE_GROUP = 0x10,
    TLV_TYPE_ADD_MEMBER = 0x11,
    TLV_TYPE_PUBLISH_KEY = 0x12,
    TLV_TYPE_CLOSE_STREAM = 0x13,
    TLV_TYPE_EDIT_MEMBER = 0x14,
    TLV_TYPE_DERIVE = 0x15,

    // Key descriptions
    TLV_TYPE_DEFAULT_KEY_DESC = 0x40,

    // Agreement protocols
    TLV_TYPE_DEFAULT_AGGREEMENT = 0x60,

} tlv_type_e;

typedef struct {
    uint8_t type;
    uint8_t length;
    const uint8_t *value;
} tlv_t;

/**
 * Read next TLV from buffer.
 */
bool tlv_read_next(buffer_t *buffer, tlv_t *tlv);

bool tlv_read_varint_u8(tlv_t *tlv, uint8_t *out);

bool tlv_read_varint_u16(tlv_t *tlv, uint16_t *out);

bool tlv_read_varint_u32(tlv_t *tlv, uint32_t *out);

bool tlv_read_hash(tlv_t *tlv, uint8_t *out);

bool tlv_read_pubkey(tlv_t *tlv, uint8_t *out);

bool tlv_read_bytes(tlv_t *tlv, uint8_t *out, size_t out_size);

bool tlv_read_string(tlv_t *tlv, char *out, size_t out_size);

bool tlv_read_signature(tlv_t *tlv, uint8_t *out, size_t out_size);