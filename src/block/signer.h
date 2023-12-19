#pragma once

#include "../stream/stream.h"
#include "types.h"

typedef enum {
    BS_INVALID_PARENT_HASH = -16,
    BS_INVALID_ISSUER = -17,
    BS_INVALID_STATE = -18,
    BS_EMPTY_BLOCK = -19,
    BS_COMMAND_COUNT_MISMATCH = -20,
} signer_state_t;

#define SIGNER_EMPTY_BLOCK 0

#define IS_SESSION_INITIALIAZED() \
    (G_context.signer_info.session_key[0] == 0x02 || G_context.signer_info.session_key[0] == 0x03)

int signer_init(signer_ctx_t *signer);

void signer_reset(void);

/**
 * Parse block header and start computing the digest
 */
int signer_parse_block_header(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data);

/**
 * Parse command and compute digest. Once parsed the command the command
 * asks for validation and output of trusted params
 */
int signer_parse_command(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data);

/**
 * Sign the block
 */
int signer_sign_block(signer_ctx_t *signer, stream_ctx_t *stream);