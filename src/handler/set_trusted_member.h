#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "buffer.h"

/**
 * Handler for SIGN_BLOCK command.
 */
int handler_set_trusted_member(buffer_t *cdata);
