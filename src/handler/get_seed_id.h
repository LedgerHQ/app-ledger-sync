#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../types.h"
#include "buffer.h"

/**
 * Handler for GET_SEED_ID command.
 *
 */
int handler_get_seed_id(buffer_t *cdata);
