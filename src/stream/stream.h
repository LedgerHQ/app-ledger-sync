#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../constants.h"
#include "buffer.h"

#include "../crypto.h"

#ifndef TEST
#include "ledger_assert.h"
#else
#include <assert.h>
#define LEDGER_ASSERT(x, y) assert(x)
#endif

typedef enum {
    STREAM_PARSING_STATE_NONE = 0x00,
    STREAM_PARSING_STATE_BLOCK_HEADER = 0x01,
    STREAM_PARSING_STATE_COMMAND = 0x02,
    STREAM_PARSING_STATE_SIGNATURE = 0x03,
} stream_parsing_state_t;

typedef enum {
    SP_OK = 0x00,
    SP_ERR_INVALID_STREAM = -1,
    SP_ERR_INVALID_STATE = -2,
    SP_ERR_UNKNOWN_COMMAND = -3,
    SP_ERR_FAILED_TO_DIGEST = -4
} stream_parser_error_t;

typedef struct {
    uint8_t member_key[MEMBER_KEY_LEN];  // Member key
    uint32_t permissions;                // Permissions of the member
    uint8_t owns_key;                    // 1 if the member owns the key, 0 otherwise
} stream_trusted_member_t;

// The stream state a block's commands change. Commands are unauthenticated while they are
// parsed, and a host is free to walk away from a block it never signs, so they write the live
// copy of these fields only; the committed copy moves forward when the block signature verifies.
typedef struct {
    uint8_t shared_secret[XPRIV_LEN];
    uint8_t shared_secret_len;
    uint8_t expected_group_key[MEMBER_KEY_LEN];
    bool awaiting_group_key;
    uint32_t app_id;
    stream_trusted_member_t trusted_member;
    bool is_created;
    bool is_closed;
} stream_block_effects_t;

typedef struct {
    // Information about the state of the stream
    uint8_t topic[MAX_TOPIC_LEN];       // Topic of the chain
    uint8_t topic_len;                  // Length of the topic
    uint8_t last_block_hash[HASH_LEN];  // Hash of the last block of the chain
    bool is_created;                    // Stream contains a create group command
    bool is_closed;                     // Stream contains a close group command
    uint8_t shared_secret[XPRIV_LEN];   // Shared secret between members of the chain
    uint8_t
        shared_secret_len;  // Length of the shared secret (0 means we don't have a shared secret)
    uint8_t device_public_key[MEMBER_KEY_LEN];  // Issuer public key

    // AppID extracted from the Derive block path
    uint32_t app_id;

    // Group key of a stream created by another member: the device holds no secret for it
    // until a publication addressed to the device delivers one matching this key
    uint8_t expected_group_key[MEMBER_KEY_LEN];
    bool awaiting_group_key;

    // Last recorded trusted member
    stream_trusted_member_t trusted_member;

    // The block-effect fields above as of the last block whose signature verified
    stream_block_effects_t committed;

    // Stamped into every trusted member issued; advanced when a block is dropped unsigned
    uint32_t trusted_member_generation;

    // Information about the current block being parsed
    uint8_t current_block_issuer[MEMBER_KEY_LEN];  // Issuer of the current block
    uint8_t current_block_length;                  // Number of instruction in the current block
    uint8_t parsed_command_count;                  // Number of command parsed in the current block
    stream_parsing_state_t parsing_state;          // Current state of the stream parser
    crypto_hash_t digest;                          // Current block digest (for hash to sign)
    crypto_hash_t full_block_digest;               // Full block digest
} stream_ctx_t;

/**
 * Initialize a stream context.
 */
void stream_init(stream_ctx_t *ctx);

/**
 * Parse a block header and add it to the stream.
 */
int stream_parse_block_header(stream_ctx_t *ctx, buffer_t *data);

/**
 * Parse a command and output trusted param
 * @param ctx Stream context
 * @param data Data to parse
 * @param trusted_data Trusted data to output (NULL if we don't want to output trusted data)
 */
int stream_parse_command(stream_ctx_t *ctx,
                         buffer_t *data,
                         uint8_t *trusted_data,
                         size_t trusted_data_len);

/**
 * Parse a signature and verifies if the stream has not been tampered with.
 */
int stream_parse_signature(stream_ctx_t *ctx, buffer_t *data);
