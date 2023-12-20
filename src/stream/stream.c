#include "stream.h"
#include "cx.h"
#include <string.h>
#include "types.h"
#include "block_parser.h"
#include "block_hasher.h"
#include "../crypto.h"
#include "../block/trusted_properties.h"

void stream_init(stream_ctx_t *ctx) {
    // Expect the next item to be a block header
    ctx->parsing_state = STREAM_PARSING_STATE_BLOCK_HEADER;

    // Initialize the hash context
    crypto_digest_init(&ctx->digest);
    crypto_digest_init(&ctx->full_block_digest);
    PRINTF("INIT STREAM\n");
}

static int verify_block_parent_hash(stream_ctx_t *ctx, uint8_t *parent_hash) {
    if (!ctx->is_created) {
        return 1;
    }
    return memcmp(ctx->last_block_hash, parent_hash, HASH_LEN) == 0;
}

int stream_parse_block_header(stream_ctx_t *ctx, buffer_t *data) {
    block_header_t header;
    int err = 0;
    PRINTF("PARSE BLOCK HEADER 1\n");
    if (ctx->parsing_state != STREAM_PARSING_STATE_BLOCK_HEADER) {
        return SP_ERR_INVALID_STATE;
    }
    PRINTF("PARSE BLOCK HEADER 2\n");
    err = parse_block_header(data, &header);
    if (err < 0) {
        return SP_ERR_INVALID_STREAM;
    }
    PRINTF("PARSE BLOCK HEADER 3\n");
    // If the stream is created, expect the parent hash to be equal to context parent hash
    if (ctx->is_created &&
        memcmp(header.parent, ctx->last_block_hash, sizeof(header.parent)) != 0) {
        return SP_ERR_INVALID_STREAM;
    }
    PRINTF("PARSE BLOCK HEADER 4\n");
    PRINTF("BLOCK ISSUER: %.*H", MEMBER_KEY_LEN, header.issuer);
    PRINTF("DEVICE KEY: %.*H", MEMBER_KEY_LEN, ctx->device_public_key);
    // If the stream is created we expect the issuer of the block to be a trusted member
    if (ctx->is_created &&
        memcmp(header.issuer, ctx->trusted_member.member_key, sizeof(header.issuer)) != 0 &&
        memcmp(header.issuer, ctx->device_public_key, sizeof(header.issuer)) != 0) {
        return SP_ERR_INVALID_STREAM;
    }
    PRINTF("PARSE BLOCK HEADER 5\n");
    // Update context
    memcpy(ctx->current_block_issuer, header.issuer, sizeof(header.issuer));
    ctx->current_block_length = header.length;
    ctx->parsed_command_count = 0;

    // Digest block header
    err = block_hash_header(&header, &ctx->digest);
    block_hash_header(&header, &ctx->full_block_digest);
    if (err != 0) {
        return SP_ERR_FAILED_TO_DIGEST;
    }
    PRINTF("PARSE BLOCK HEADER 6\n");
    // Verify if block parent is right
    if (verify_block_parent_hash(ctx, header.parent) != 1) {
        return SP_ERR_INVALID_STREAM;
    }

    // Expect a command to be sent next
    ctx->parsing_state = STREAM_PARSING_STATE_COMMAND;
    return SP_OK;
}

inline static int stream_parse_seed_command(stream_ctx_t *ctx,
                                            block_command_t *command,
                                            uint8_t *trusted_data,
                                            size_t trusted_data_len) {
    int ret = CX_OK;
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};

    PRINTF("BLOCK ISSUER: %.*H", MEMBER_KEY_LEN, ctx->current_block_issuer);
    PRINTF("DEVICE KEY: %.*H", MEMBER_KEY_LEN, ctx->device_public_key);

    // If the command was issued by the device, save the seed in the stream context
    // otherwise create and return a trusted member
    if (memcmp(ctx->current_block_issuer, ctx->device_public_key, MEMBER_KEY_LEN) == 0) {
        // Initialize private key
        ret = crypto_derive_private_key(&private_key, chain_code, SEED_ID_PATH, SEED_ID_PATH_LEN);
        if (ret != CX_OK) {
            explicit_bzero(&private_key, sizeof(private_key));
            return ret;
        }
        // Decrypt the seed
        ctx->shared_secret_len = crypto_ecdhe_decrypt(&private_key,
                                                      command->command.seed.ephemeral_public_key,
                                                      command->command.seed.encrypted_xpriv,
                                                      sizeof(command->command.seed.encrypted_xpriv),
                                                      command->command.seed.initialization_vector,
                                                      ctx->shared_secret,
                                                      sizeof(ctx->shared_secret));
        explicit_bzero(&private_key, sizeof(private_key));
        if (ctx->shared_secret_len != 2 * PRIVATE_KEY_LEN) {
            return SP_ERR_INVALID_STREAM;
        }
        PRINTF("STREAM SHARED SECRET: %.*H", ctx->shared_secret_len, ctx->shared_secret);
    } else {
        // Issue a trusted member for the issuer
        memcpy(ctx->trusted_member.member_key, ctx->current_block_issuer, MEMBER_KEY_LEN);
        ctx->trusted_member.owns_key = true;
        ctx->trusted_member.permissions = OWNER;
        ret = serialize_trusted_member(&ctx->trusted_member, trusted_data, trusted_data_len);
    }

    // Update the stream context
    ctx->is_created = true;
    return ret;
}

inline static int stream_parse_derive_command(stream_ctx_t *ctx,
                                              block_command_t *command,
                                              uint8_t *trusted_data,
                                              size_t trusted_data_len) {
    (void) trusted_data;
    (void) trusted_data_len;
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    int ret = CX_OK;

    // If the command was issued by the device, save the seed in the stream context
    if (memcmp(ctx->current_block_issuer, ctx->device_public_key, MEMBER_KEY_LEN) == 0) {
        // Initialize private key
        ret = crypto_derive_private_key(&private_key, chain_code, SEED_ID_PATH, SEED_ID_PATH_LEN);
        if (ret != CX_OK) {
            explicit_bzero(&private_key, sizeof(private_key));
            return ret;
        }
        // Decrypt the xpriv
        ctx->shared_secret_len =
            crypto_ecdhe_decrypt(&private_key,
                                 command->command.derive.ephemeral_public_key,
                                 command->command.derive.encrypted_xpriv,
                                 sizeof(command->command.derive.encrypted_xpriv),
                                 command->command.derive.initialization_vector,
                                 ctx->shared_secret,
                                 sizeof(ctx->shared_secret));
        explicit_bzero(&private_key, sizeof(private_key));
        if (ctx->shared_secret_len != 2 * PRIVATE_KEY_LEN) {
            return SP_ERR_INVALID_STREAM;
        }
        PRINTF("STREAM SHARED SECRET (from derivation): %.*H",
               ctx->shared_secret_len,
               ctx->shared_secret);
        return SP_OK;
    }

    // Nothing to update in the stream context
    return SP_OK;
}

inline static int stream_parse_add_member_command(stream_ctx_t *ctx,
                                                  block_command_t *command,
                                                  uint8_t *trusted_data,
                                                  size_t trusted_data_len) {
    // If the command was issued for the device, save the key in the stream context
    if (memcmp(command->command.add_member.public_key, ctx->device_public_key, MEMBER_KEY_LEN) ==
        0) {
        // Decrypt the key
        // TODO IMPLEMENT
        return SP_OK;
    }
    // Otherwise, issue a trusted member
    memcpy(ctx->trusted_member.member_key, command->command.add_member.public_key, MEMBER_KEY_LEN);
    ctx->trusted_member.owns_key = false;
    ctx->trusted_member.permissions = command->command.add_member.permissions;
    return serialize_trusted_member(&ctx->trusted_member, trusted_data, trusted_data_len);
}

inline static int stream_parse_publish_key_command(stream_ctx_t *ctx,
                                                   block_command_t *command,
                                                   uint8_t *trusted_data,
                                                   size_t trusted_data_len) {
    // Nothing to be done if the recipient is the device
    if (memcmp(command->command.publish_key.recipient, ctx->device_public_key, MEMBER_KEY_LEN) ==
        0) {
        return SP_OK;
    }

    // Update the trusted member if the member was set
    if (memcmp(command->command.publish_key.recipient,
               ctx->trusted_member.member_key,
               MEMBER_KEY_LEN) != 0) {
        return SP_OK;  // Trusted member was not set, nothing to be done
    }
    ctx->trusted_member.owns_key = true;
    return serialize_trusted_member(&ctx->trusted_member, trusted_data, trusted_data_len);
}

inline static int stream_parse_edit_member_command(stream_ctx_t *ctx,
                                                   block_command_t *command,
                                                   uint8_t *trusted_data,
                                                   size_t trusted_data_len) {
    // Update the trusted member if the member was set
    // NOT IMPLEMENTED
    (void) ctx;
    (void) command;
    (void) trusted_data;
    (void) trusted_data_len;
    return -1;
}

inline static int stream_parse_close_stream_command(stream_ctx_t *ctx,
                                                    block_command_t *command,
                                                    uint8_t *trusted_data,
                                                    size_t trusted_data_len) {
    (void) command;
    (void) trusted_data;
    (void) trusted_data_len;

    // Update the stream context
    ctx->is_closed = true;
    return SP_OK;
}

int stream_parse_command(stream_ctx_t *ctx,
                         buffer_t *data,
                         uint8_t *trusted_data,
                         size_t trusted_data_len) {
    int err = SP_OK;
    int length = 0;
    block_command_t command;

    if (ctx->parsing_state != STREAM_PARSING_STATE_COMMAND) {
        return SP_ERR_INVALID_STATE;
    }

    // Parse command
    err = parse_block_command(data, &command);
    if (err < 0) {
        return SP_ERR_INVALID_STREAM;
    }

    // If the stream.is_created is false, only the seed command is allowed.
    if (!ctx->is_created && command.type != COMMAND_SEED) {
        return SP_ERR_INVALID_STREAM;
    }

    switch (command.type) {
        case COMMAND_SEED:
            length = stream_parse_seed_command(ctx, &command, trusted_data, trusted_data_len);
            break;
        case COMMAND_DERIVE:
            length = stream_parse_derive_command(ctx, &command, trusted_data, trusted_data_len);
            break;
        case COMMAND_ADD_MEMBER:
            length = stream_parse_add_member_command(ctx, &command, trusted_data, trusted_data_len);
            break;
        case COMMAND_PUBLISH_KEY:
            length =
                stream_parse_publish_key_command(ctx, &command, trusted_data, trusted_data_len);
            break;
        case COMMAND_EDIT_MEMBER:
            length =
                stream_parse_edit_member_command(ctx, &command, trusted_data, trusted_data_len);
            break;
        case COMMAND_CLOSE_STREAM:
            length =
                stream_parse_close_stream_command(ctx, &command, trusted_data, trusted_data_len);
            break;
        default:
            break;
    }

    // Digest command
    err = block_hash_command(&command, &ctx->digest);
    block_hash_command(&command, &ctx->full_block_digest);
    if (err < 0) {
        return SP_ERR_INVALID_STREAM;
    }
    // Update context
    ctx->parsed_command_count += 1;

    // If we have parsed all commands, expect a signature to be sent next
    if (ctx->parsed_command_count >= ctx->current_block_length) {
        ctx->parsing_state = STREAM_PARSING_STATE_SIGNATURE;
    }

    if (length == TP_BUFFER_OVERFLOW) {
        return 0;
    }
    return err == SP_OK ? length : err;
}

int stream_parse_signature(stream_ctx_t *ctx, buffer_t *data) {
    (void) data;
    (void) ctx;
    uint8_t signature[MAX_DER_SIG_LEN] = {0};
    int signature_len = 0;

    signature_len = parse_block_signature(data, signature, sizeof(signature));
    if (signature_len < 0) {
        return SP_ERR_INVALID_STREAM;
    }
    if (crypto_verify_signature(ctx->current_block_issuer,
                                &ctx->digest,
                                signature,
                                signature_len) != 1) {
        return SP_ERR_INVALID_STREAM;
    }
    block_hash_signature(signature, signature_len, &ctx->full_block_digest);
    crypto_digest_finalize(&ctx->full_block_digest,
                           ctx->last_block_hash,
                           sizeof(ctx->last_block_hash));
    return 0;
}