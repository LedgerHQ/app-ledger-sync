#pragma once

#include "os.h"
#include "../crypto.h"
#include "types.h"
#include "block_parser.h"

void block_hash_header(const block_header_t *header, crypto_hash_t *digest);
int block_hash_command(const block_command_t *command, crypto_hash_t *digest);
void block_hash_signature(const uint8_t *signature, size_t signature_len, crypto_hash_t *digest);