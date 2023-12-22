#pragma once

#include <stdint.h>
#include "buffer.h"

#include "../handler/get_seed_id.h"
#include "challenge_parser.h"
int verify_challenge_signature(challenge_ctx_t* challenge_ctx, uint8_t* challenge_hash);

int sign_challenge(uint8_t* challenge_hash);
