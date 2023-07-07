#include "signer.h"
#include "block_parser.h"
#include <string.h>
#include "cx.h"
#include "crypto.h"
#include "debug.h"
#include "../io.h"
#include "block_hasher.h"
#include "trusted_properties.h"
#include "../globals.h"

int signer_init(signer_ctx_t *signer) {
    crypto_digest_init(&signer->digest);
    return SP_OK;
}

void signer_reset() {
    DEBUG_PRINT("RESET SIGNER\n")
    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));
    explicit_bzero(&G_context.stream, sizeof(G_context.stream));
}

// TODO REMOVE STATIC PATH

static bool signer_verify_parent_hash(stream_ctx_t *stream, uint8_t *parent_hash) {
    uint8_t hash[HASH_LEN];

    crypto_digest_finalize(&stream->digest, hash, sizeof(hash));
    return memcmp(hash, parent_hash, sizeof(hash)) == 0;
}

int signer_parse_block_header(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data) {
    (void) signer;
    // Parse the block header
    block_header_t block_header;
    int err = parse_block_header(data, &block_header);

    if (!err) {
        return err;
    }
    if (block_header.length == 0) {
        signer_reset();
        return BS_EMPTY_BLOCK;
    }

    // Verify the parent is set to the current block hash (if stream is created)

    if (stream->is_created && !signer_verify_parent_hash(stream, block_header.parent)) {
        return BS_INVALID_PARENT_HASH;
    }

    // Set the block issuer
    memcpy(block_header.issuer, stream->device_public_key, MEMBER_KEY_LEN);

    // Set block count in the signer
    signer->command_count = block_header.length;

    // Digest block header
    block_hash_header(&block_header, &signer->digest);
    return 0;
}

static int signer_inject_seed(signer_ctx_t *signer, block_command_t *command) {
    (void) signer;
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;
    uint8_t xpriv[64];
    //cx_aes_key_t key;
    uint8_t secret[32];
    buffer_t buffer;
    int ret = 0;
    
    // Generate private key
    ret = cx_ecfp_generate_pair(CX_CURVE_256K1, &public_key, &private_key, 0);
    if (ret != 0)
        return ret;

    // Generate chain code
    cx_trng_get_random_data(xpriv + 32, 32);

    // Create ephemeral ECDH
    ret = crypto_ephemeral_ecdh(G_context.stream.device_public_key, command->command.seed.ephemeral_public_key, secret);
    if (ret != 0)
        return ret;

    // Generate IV
    cx_trng_get_random_data(command->command.seed.initialization_vector, sizeof(command->command.seed.initialization_vector));

    // Write private key in xpriv buffer
    memcpy(xpriv, private_key.d, sizeof(private_key.d));

    // Encrypt xpriv
    // ret = cx_aes_init_key(secret, sizeof(secret), &key);
    // if (ret < 0)
    //     return ret;
    // cx_aes_iv(
    //     &key, 
    //     CX_ENCRYPT | CX_CHAIN_CBC | CX_LAST, 
    //     command->command.seed.initialization_vector,
    //     sizeof(command->command.seed.initialization_vector),
    //     xpriv, 
    //     sizeof(xpriv), 
    //     command->command.seed.encrypted_xpriv,
    //     sizeof(command->command.seed.encrypted_xpriv)
    // );
    uint8_t test[64];
    DEBUG_LOG_BUF("XPRIV BEFORE: ", xpriv, sizeof(xpriv));
    ret = crypto_encrypt(secret, sizeof(secret), xpriv, sizeof(xpriv), command->command.seed.initialization_vector,
                   command->command.seed.encrypted_xpriv, sizeof(command->command.seed.encrypted_xpriv), false);

    crypto_decrypt(secret, sizeof(secret), command->command.seed.encrypted_xpriv, sizeof(command->command.seed.encrypted_xpriv), command->command.seed.initialization_vector,
                   test, sizeof(xpriv), false);
    DEBUG_LOG_BUF("ENC XPRIX AFTER: ", command->command.seed.encrypted_xpriv, sizeof(xpriv));
    DEBUG_LOG_BUF("XPRIV AFTER: ", test, sizeof(xpriv));
    if (ret < 0)
        return ret;
    command->command.seed.encrypted_xpriv_size = sizeof(command->command.seed.encrypted_xpriv);

    // Compress and save group key
    crypto_compress_public_key(public_key.W, command->command.seed.group_public_key);

    // Push trusted properties
    // - push encrypted xpriv
    buffer.ptr = command->command.seed.encrypted_xpriv;
    buffer.size = sizeof(command->command.seed.encrypted_xpriv);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_XPRIV, &buffer);
    if (ret != 0)
        return ret;
    // - push ephemeral public key
    buffer.ptr = command->command.seed.ephemeral_public_key;
    buffer.size = sizeof(command->command.seed.ephemeral_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_EPHEMERAL_PUBLIC_KEY, &buffer);
    if (ret != 0)
        return ret;

    // - push initialization vector
    buffer.ptr = command->command.seed.initialization_vector;
    buffer.size = sizeof(command->command.seed.initialization_vector);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_COMMAND_IV, &buffer);
    if (ret != 0)
        return ret;

    // - push group key
    buffer.ptr = command->command.seed.group_public_key;
    buffer.size = sizeof(command->command.seed.group_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_GROUPKEY, &buffer);
    if (ret != 0)
        return ret;

    explicit_bzero(&private_key, sizeof(private_key));

    // User approval
    // TODO implement user approval

    return ret < 0 ? ret : 0;
}

static int signer_inject_add_member(signer_ctx_t *signer, block_command_t *command) {
    (void)signer;
    uint8_t buffer[TP_BUFFER_SIZE_NEW_MEMBER];
    buffer_t trusted_property = {
        .ptr = buffer,
        .size = sizeof(buffer),
        .offset = 0
    };

    // Ask user approval and return the command as trusted property

    // User approval
    // TODO implement user approval

    // Push trusted property
    memcpy(G_context.stream.trusted_member.member_key, command->command.add_member.public_key, MEMBER_KEY_LEN);
    G_context.stream.trusted_member.owns_key = 0;
    G_context.stream.trusted_member.permissions = command->command.add_member.permissions;
    serialize_trusted_member(&G_context.stream.trusted_member, buffer, sizeof(buffer));
    return io_push_trusted_property(TP_NEW_MEMBER, &trusted_property);
}

int signer_parse_command(signer_ctx_t *signer,
                         stream_ctx_t *stream,
                         buffer_t *data) {
    block_command_t command;
    DEBUG_PRINT("SIGNER PARSE COMMAND\n")
    if (signer->command_count <= SIGNER_EMPTY_BLOCK) {
        signer_reset();
        return BS_EMPTY_BLOCK;
    }

    int err = parse_block_command(data, &command);

    if (err < 0) {
        signer_reset();
        return err;
    }

    // First pass: inject data in command buffer
    io_init_trusted_property();
    if (command.type == COMMAND_SEED) {
        if (stream->is_created) {
            return BS_INVALID_STATE;
        }
        stream->is_created = true;
        stream->topic_len = command.command.seed.topic_len;
        memcpy(stream->topic,
               command.command.seed.topic,
               command.command.seed.topic_len);
        err = signer_inject_seed(signer, &command);
    } else if (command.type == COMMAND_ADD_MEMBER) {
        DEBUG_PRINT("SIGNER PARSE COMMAND ADD MEMBER\n")
        if (!stream->is_created) {
            return BS_INVALID_STATE;
        }
        err = signer_inject_add_member(signer, &command);
    } else {
        return BP_ERROR_UNKNOWN_COMMAND;
    }
    
    if (err != 0) {
        signer_reset();
        return err;
    }

    // Digest command
    block_hash_command(&command, &signer->digest);

    signer->parsed_command += 1;
    return 0;
}

int signer_approve_command(stream_ctx_t *stream, buffer_t *trusted_data) {
    (void) stream;
    (void) trusted_data;

    return 0;
}

int signer_sign_block(signer_ctx_t *signer, stream_ctx_t *stream) {
    // Finalize hashing and put it in stream last block hash
    
    if (signer->command_count <= SIGNER_EMPTY_BLOCK) {
        signer_reset();
        return BS_EMPTY_BLOCK;
    }

    if (signer->command_count != signer->parsed_command) {
        signer_reset();
        return BS_COMMAND_COUNT_MISMATCH;
    }

    crypto_digest_finalize(&signer->digest, stream->last_block_hash, sizeof(stream->last_block_hash));
    // Sign the block
    return crypto_sign_block();
}