#include "stream.h"
#include "cx.h"
#include <string.h>
#include "types.h"
#include "block_parser.h"
#include "block_hasher.h"
#include "../crypto.h"
#include "../block/trusted_properties.h"

// clang-format off
typedef enum {
    MEMBER_TYPE_SELF,
    MEMBER_TYPE_TRUSTED,
    MEMBER_TYPE_UNKNOWN
} member_type_t;
// clang-format on

static member_type_t get_member_type(stream_ctx_t *ctx, uint8_t *member_key) {
    if (memcmp(member_key, ctx->device_public_key, MEMBER_KEY_LEN) == 0) {
        return MEMBER_TYPE_SELF;
    }
    if (memcmp(member_key, ctx->trusted_member.member_key, MEMBER_KEY_LEN) == 0) {
        return MEMBER_TYPE_TRUSTED;
    }
    return MEMBER_TYPE_UNKNOWN;
}

// Promote what the current block changed: its issuer signature has just been verified.
static void stream_commit_block_effects(stream_ctx_t *ctx) {
    memcpy(ctx->committed.shared_secret, ctx->shared_secret, sizeof(ctx->shared_secret));
    ctx->committed.shared_secret_len = ctx->shared_secret_len;
    memcpy(ctx->committed.expected_group_key,
           ctx->expected_group_key,
           sizeof(ctx->expected_group_key));
    ctx->committed.awaiting_group_key = ctx->awaiting_group_key;
    ctx->committed.app_id = ctx->app_id;
    ctx->committed.trusted_member = ctx->trusted_member;
    ctx->committed.is_created = ctx->is_created;
    ctx->committed.is_closed = ctx->is_closed;
}

// Discard what a block changed without ever proving who issued it.
static void stream_rollback_block_effects(stream_ctx_t *ctx) {
    memcpy(ctx->shared_secret, ctx->committed.shared_secret, sizeof(ctx->shared_secret));
    ctx->shared_secret_len = ctx->committed.shared_secret_len;
    memcpy(ctx->expected_group_key,
           ctx->committed.expected_group_key,
           sizeof(ctx->expected_group_key));
    ctx->awaiting_group_key = ctx->committed.awaiting_group_key;
    ctx->app_id = ctx->committed.app_id;
    ctx->trusted_member = ctx->committed.trusted_member;
    ctx->is_created = ctx->committed.is_created;
    ctx->is_closed = ctx->committed.is_closed;
}

// Return the parser to a block boundary, dropping any block left unsigned
static void stream_reset_to_boundary(stream_ctx_t *ctx) {
    // Trusted members issued while that block was parsed must not be accepted back
    if (ctx->parsing_state == STREAM_PARSING_STATE_COMMAND ||
        ctx->parsing_state == STREAM_PARSING_STATE_SIGNATURE) {
        ctx->trusted_member_generation += 1;
    }
    stream_rollback_block_effects(ctx);
    ctx->parsing_state = STREAM_PARSING_STATE_BLOCK_HEADER;
    crypto_digest_init(&ctx->digest);
    crypto_digest_init(&ctx->full_block_digest);
}

void stream_init(stream_ctx_t *ctx) {
    stream_reset_to_boundary(ctx);
    PRINTF("INIT STREAM\n");
}

static int verify_block_parent_hash(stream_ctx_t *ctx, uint8_t *parent_hash) {
    LEDGER_ASSERT(ctx != NULL, "Null ctx\n");
    LEDGER_ASSERT(parent_hash != NULL, "Null parent_hash\n");

    if (!ctx->is_created) {
        return 1;
    }

    return memcmp(ctx->last_block_hash, parent_hash, HASH_LEN) == 0;
}

int stream_parse_block_header(stream_ctx_t *ctx, buffer_t *data) {
    block_header_t header = {0};
    member_type_t member_type;
    int err = 0;

    LEDGER_ASSERT(ctx != NULL, "Null ctx\n");

    if (ctx->parsing_state != STREAM_PARSING_STATE_BLOCK_HEADER) {
        return SP_ERR_INVALID_STATE;
    }
    // A stream whose CLOSE_STREAM block has been authenticated has no successor to replay
    if (ctx->is_closed) {
        PRINTF("Stream is closed\n");
        return SP_ERR_INVALID_STATE;
    }
    err = parse_block_header(data, &header);
    if (err < 0) {
        return SP_ERR_INVALID_STREAM;
    }
    // If the stream is created, expect the parent hash to be equal to context parent hash
    if (ctx->is_created &&
        memcmp(header.parent, ctx->last_block_hash, sizeof(header.parent)) != 0) {
        return SP_ERR_INVALID_STREAM;
    }
    // If the stream is created we expect the issuer of the block to be a trusted member
    // and that it can add blocks
    member_type = get_member_type(ctx, header.issuer);
    if (ctx->is_created && member_type == MEMBER_TYPE_UNKNOWN) {
        return SP_ERR_INVALID_STREAM;
    }
    if (member_type == MEMBER_TYPE_TRUSTED &&
        (ctx->trusted_member.permissions & CAN_ADD_BLOCK) == 0) {
        return SP_ERR_INVALID_STREAM;
    }
    // Update context
    memcpy(ctx->current_block_issuer, header.issuer, sizeof(header.issuer));
    ctx->current_block_length = header.length;
    ctx->parsed_command_count = 0;

    // Digest block header
    block_hash_header(&header, &ctx->digest);
    block_hash_header(&header, &ctx->full_block_digest);

    // Verify if block parent is right
    if (verify_block_parent_hash(ctx, header.parent) != 1) {
        return SP_ERR_INVALID_STREAM;
    }

    // Expect a command to be sent next
    ctx->parsing_state = STREAM_PARSING_STATE_COMMAND;
    return SP_OK;
}

// A stream created by another member does not hand its secret over in the creating command.
// The parent secret loaded while walking down to it belongs to another subtree, so it must not
// stay usable here: it would be published as if it were this stream's key.
static void stream_await_group_key(stream_ctx_t *ctx, const uint8_t *group_public_key) {
    explicit_bzero(ctx->shared_secret, sizeof(ctx->shared_secret));
    ctx->shared_secret_len = 0;
    memcpy(ctx->expected_group_key, group_public_key, MEMBER_KEY_LEN);
    ctx->awaiting_group_key = true;
}

static void stream_hold_group_key(stream_ctx_t *ctx) {
    explicit_bzero(ctx->expected_group_key, sizeof(ctx->expected_group_key));
    ctx->awaiting_group_key = false;
}

inline static int stream_parse_seed_command(stream_ctx_t *ctx,
                                            block_command_t *command,
                                            uint8_t *trusted_data,
                                            size_t trusted_data_len) {
    cx_err_t error = CX_INTERNAL_ERROR;

    // Root material is shared by every application subtree, so it carries no policy of its own
    ctx->app_id = APP_ID_NONE;

    PRINTF("BLOCK ISSUER: %.*H", MEMBER_KEY_LEN, ctx->current_block_issuer);
    PRINTF(" DEVICE KEY: %.*H\n", MEMBER_KEY_LEN, ctx->device_public_key);

    // If the command was issued by the device, save the seed in the stream context
    // otherwise create and return a trusted member
    if (memcmp(ctx->current_block_issuer, ctx->device_public_key, MEMBER_KEY_LEN) == 0) {
        // Decrypt the seed
        ctx->shared_secret_len = crypto_ecdh_decrypt(command->command.seed.ephemeral_public_key,
                                                     command->command.seed.encrypted_xpriv,
                                                     sizeof(command->command.seed.encrypted_xpriv),
                                                     command->command.seed.initialization_vector,
                                                     ctx->shared_secret,
                                                     sizeof(ctx->shared_secret));
        if (ctx->shared_secret_len != XPRIV_LEN) {
            error = SP_ERR_INVALID_STREAM;
            goto end;
        }
        error = SP_OK;
        stream_hold_group_key(ctx);
        PRINTF("STREAM SHARED SECRET: %.*H\n", ctx->shared_secret_len, ctx->shared_secret);
    } else {
        stream_await_group_key(ctx, command->command.seed.group_public_key);
        // Issue a trusted member for the issuer
        memcpy(ctx->trusted_member.member_key, ctx->current_block_issuer, MEMBER_KEY_LEN);
        ctx->trusted_member.owns_key = true;
        ctx->trusted_member.permissions = OWNER;
        error = serialize_trusted_member(&ctx->trusted_member,
                                         ctx->trusted_member_generation,
                                         trusted_data,
                                         trusted_data_len);
    }

    // Update the stream context
    ctx->is_created = true;
end:
    return error;
}

inline static int stream_parse_derive_command(stream_ctx_t *ctx, block_command_t *command) {
    cx_err_t error = CX_INTERNAL_ERROR;

    // Extract AppID from path[1] (format: {treeIndex}h/{appId}h/...)
    if (command->command.derive.path_len > 1) {
        ctx->app_id = command->command.derive.path[1] & 0x7FFFFFFF;
    } else {
        ctx->app_id = APP_ID_NONE;
    }

    // If the command was issued by the device, save the seed in the stream context
    if (memcmp(ctx->current_block_issuer, ctx->device_public_key, MEMBER_KEY_LEN) == 0) {
        // Decrypt the xpriv
        ctx->shared_secret_len =
            crypto_ecdh_decrypt(command->command.derive.ephemeral_public_key,
                                command->command.derive.encrypted_xpriv,
                                sizeof(command->command.derive.encrypted_xpriv),
                                command->command.derive.initialization_vector,
                                ctx->shared_secret,
                                sizeof(ctx->shared_secret));
        if (ctx->shared_secret_len != 2 * PRIVATE_KEY_LEN) {
            error = SP_ERR_INVALID_STREAM;
            goto end;
        }
        stream_hold_group_key(ctx);
        PRINTF("STREAM SHARED SECRET (from derivation): %.*H",
               ctx->shared_secret_len,
               ctx->shared_secret);
    } else {
        stream_await_group_key(ctx, command->command.derive.group_public_key);
    }

    // Nothing to update in the stream context
    error = SP_OK;
end:
    return error;
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
    return serialize_trusted_member(&ctx->trusted_member,
                                    ctx->trusted_member_generation,
                                    trusted_data,
                                    trusted_data_len);
}

// Install the xpriv a member published to this device. The command is not authenticated at this
// point, so the decrypted key is only accepted when it reproduces the group key of the command
// that created the stream; anything else would let a host choose the stream secret.
static int stream_install_published_key(stream_ctx_t *ctx, block_command_t *command) {
    uint8_t xpriv[XPRIV_LEN] = {0};
    uint8_t group_public_key[MEMBER_KEY_LEN] = {0};
    int error = SP_ERR_INVALID_STREAM;

    if (crypto_ecdh_decrypt(command->command.publish_key.ephemeral_public_key,
                            command->command.publish_key.encrypted_xpriv,
                            command->command.publish_key.encrypted_xpriv_size,
                            command->command.publish_key.initialization_vector,
                            xpriv,
                            sizeof(xpriv)) != XPRIV_LEN) {
        goto end;
    }
    crypto_compressed_public_key_from_private(xpriv, group_public_key);
    if (memcmp(group_public_key, ctx->expected_group_key, MEMBER_KEY_LEN) != 0) {
        PRINTF("Published key does not match the stream group key\n");
        goto end;
    }

    memcpy(ctx->shared_secret, xpriv, sizeof(xpriv));
    ctx->shared_secret_len = sizeof(xpriv);
    stream_hold_group_key(ctx);
    error = SP_OK;
end:
    explicit_bzero(xpriv, sizeof(xpriv));
    return error;
}

inline static int stream_parse_publish_key_command(stream_ctx_t *ctx,
                                                   block_command_t *command,
                                                   uint8_t *trusted_data,
                                                   size_t trusted_data_len) {
    if (memcmp(command->command.publish_key.recipient, ctx->device_public_key, MEMBER_KEY_LEN) ==
        0) {
        // A publication addressed to the device is how it receives the secret of a stream it
        // did not create; when it already holds one there is nothing to take from the command
        if (!ctx->awaiting_group_key) {
            return SP_OK;
        }
        return stream_install_published_key(ctx, command);
    }

    // Update the trusted member if the member was set
    if (memcmp(command->command.publish_key.recipient,
               ctx->trusted_member.member_key,
               MEMBER_KEY_LEN) != 0) {
        return SP_OK;  // Trusted member was not set, nothing to be done
    }
    ctx->trusted_member.owns_key = true;
    return serialize_trusted_member(&ctx->trusted_member,
                                    ctx->trusted_member_generation,
                                    trusted_data,
                                    trusted_data_len);
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
    block_command_t command = {0};

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
            length = stream_parse_derive_command(ctx, &command);
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
    uint8_t signature[MAX_DER_SIG_LEN] = {0};
    int signature_len = 0;
    uint8_t final_digest[HASH_LEN];

    signature_len = parse_block_signature(data, signature, sizeof(signature));
    if (signature_len < 0 || signature_len > MAX_DER_SIG_LEN) {
        stream_reset_to_boundary(ctx);
        return SP_ERR_INVALID_STREAM;
    }
    crypto_digest_finalize(&ctx->digest, final_digest, sizeof(final_digest));
    if (crypto_verify_signature(ctx->current_block_issuer,
                                final_digest,
                                signature,
                                signature_len) != CX_OK) {
        stream_reset_to_boundary(ctx);
        return SP_ERR_INVALID_STREAM;
    }
    block_hash_signature(signature, signature_len, &ctx->full_block_digest);
    crypto_digest_finalize(&ctx->full_block_digest,
                           ctx->last_block_hash,
                           sizeof(ctx->last_block_hash));
    stream_commit_block_effects(ctx);
    ctx->parsing_state = STREAM_PARSING_STATE_BLOCK_HEADER;
    crypto_digest_init(&ctx->digest);
    crypto_digest_init(&ctx->full_block_digest);
    return 0;
}
