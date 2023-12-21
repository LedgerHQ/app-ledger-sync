#pragma once

#include "../stream/stream.h"

#ifndef TEST
#include "ledger_assert.h"
#else
#include <assert.h>
#define LEDGER_ASSERT(x, y) assert(x)
#endif

#define TP_CHECKSUM_LEN 4
#define TP_NONCE_SIZE   4
#define TP_BUFFER_SIZE_NEW_MEMBER \
    (TP_NONCE_SIZE + sizeof(stream_trusted_member_t) + TP_CHECKSUM_LEN)

typedef enum {
    TP_IV = 0x00,
    TP_ISSUER_PUBLIC_KEY = 0x01,
    TP_XPRIV = 0x02,
    TP_EPHEMERAL_PUBLIC_KEY = 0x03,
    TP_COMMAND_IV = 0x04,
    TP_GROUPKEY = 0x05,
    TP_NEW_MEMBER = 0x06
} tp_type_e;

typedef enum {
    TP_SUCCESS = 0x00,
    TP_UNKNOWN_COMMAND = -1,
    TP_BUFFER_OVERFLOW = -2,
    TP_FAILED_TO_HASH = -3,
    TP_INVALID_CHECKSUM = -4,
} tp_error_e;

int serialize_trusted_member(stream_trusted_member_t *member, uint8_t *buffer, size_t buffer_size);
int deserialize_trusted_member(uint8_t *buffer, size_t buffer_size, stream_trusted_member_t *out);