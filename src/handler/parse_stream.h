#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "buffer.h"

typedef enum {
    MODE_PARSE_BLOCK_HEADER = 0x00,
    MODE_PARSE_COMMAND = 0x01,
    MODE_PARSE_SIGNATURE = 0x02,
    MODE_PARSE_EMPTY_STREAM = 0x03,
} parse_stream_mode_t;

typedef enum {
    OUTPUT_MODE_NONE = 0x00,
    OUTPUT_MODE_TRUSTED_DATA = 0x01,
} parse_stream_output_mode_t;

/**
 * Handler for SIGN_BLOCK command.
 */
int handler_parse_stream(buffer_t *cdata,
                         parse_stream_mode_t parse_mode,
                         parse_stream_output_mode_t output_mode);
