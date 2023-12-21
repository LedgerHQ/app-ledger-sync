#pragma once

#include "types.h"
#include "buffer.h"

#ifndef TEST
#include "ledger_assert.h"
#else
#include <assert.h>
#define LEDGER_ASSERT(x, y) assert(x)
#endif

typedef enum {
    BP_ERROR_UNDEFINED = -1,
    BP_ERROR_UNKNOWN_COMMAND = -2,
    BP_UNEXPECTED_TLV = -3,
    BP_OVERSIZED_FIELD = -4,
    BP_UNKNOWN_ENCRYPTION_DESCRIPTION = -5,
    BP_UNKNOWN_AGREEMENT_DESCRIPTION = -6,
    BP_FAILED_TO_READ_DERIVATION_PATH = -7,
} block_parser_error_t;

int parse_block_header(buffer_t *data, block_header_t *out);
int parse_block_command(buffer_t *data, block_command_t *out);
int parse_block_signature(buffer_t *data, uint8_t *out, size_t out_len);