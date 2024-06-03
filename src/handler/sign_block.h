#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "buffer.h"

#define MODE_BLOCK_START    0x00
#define MODE_COMMAND_PARSE  0x01
#define MODE_BLOCK_FINALIZE 0x02

/**
 * Handler for SIGN_BLOCK command.
 */
int handler_sign_block(buffer_t *cdata, uint8_t mode);
