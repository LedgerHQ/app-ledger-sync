#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "secp256k1.h"

typedef struct {
    uint8_t raw[32];
} crypto_secp256k1_private_key_t;

typedef char crypto_hash_t;
typedef crypto_secp256k1_private_key_t crypto_private_key_t;
typedef secp256k1_pubkey crypto_public_key_t;
