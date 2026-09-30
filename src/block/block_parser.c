#include "block_parser.h"
#include "read.h"
#include "bip32.h"

int parse_block_header(buffer_t *data, block_header_t *out) {
    tlv_t tlv = {0};

    LEDGER_ASSERT(data != NULL, "Null data\n");

    size_t offset = data->offset;

    // Read version (1 byte)
    if (!tlv_read_next(data, &tlv) || !tlv_read_varint_u8(&tlv, &out->version)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read parent hash
    if (!tlv_read_next(data, &tlv) || !tlv_read_hash(&tlv, out->parent)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read issuer public key
    if (!tlv_read_next(data, &tlv) || !tlv_read_pubkey(&tlv, out->issuer)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read command length (1 byte)
    if (!tlv_read_next(data, &tlv) || !tlv_read_varint_u8(&tlv, &out->length)) {
        return BP_UNEXPECTED_TLV;
    }

    return data->offset - offset;
}

static int parse_seed_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv = {0};

    LEDGER_ASSERT(out != NULL, "Null out\n");

    // Read the topic
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MAX_TOPIC_LEN) {
        return BP_OVERSIZED_FIELD;
    }
    // An absent topic is encoded as a zero-length NULL TLV
    if (tlv.type == TLV_TYPE_NULL) {
        if (tlv.length != 0) {
            return BP_UNEXPECTED_TLV;
        }
    } else if (!tlv_read_bytes(&tlv, out->command.seed.topic, MAX_TOPIC_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.seed.topic_len = tlv.length;

    // Read protocol version

    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_varint_u16(&tlv, &out->command.seed.protocol_version)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read group public key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_generated_pubkey(&tlv, out->command.seed.group_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read IV
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.seed.initialization_vector, IV_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.seed.initialization_vector_size = tlv.length;

    // Read encrypted xpriv
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.seed.encrypted_xpriv, MAX_ENCRYPTED_KEY_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.seed.encrypted_xpriv_size = tlv.length;

    // Read ephemeral public key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_generated_pubkey(&tlv, out->command.seed.ephemeral_public_key))
        return BP_UNEXPECTED_TLV;

    return 0;
}

static int parse_add_member_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv = {0};

    LEDGER_ASSERT(out != NULL, "Null out\n");

    // Read member name
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MAX_NAME_LEN) {
        return BP_OVERSIZED_FIELD;
    }

    if (!tlv_read_string(&tlv,
                         out->command.add_member.name,
                         sizeof(out->command.add_member.name))) {
        return BP_UNEXPECTED_TLV;
    }

    // Read member public key
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MEMBER_KEY_LEN) {
        return BP_OVERSIZED_FIELD;
    }
    if (!tlv_read_pubkey(&tlv, out->command.add_member.public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read member permissions
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_varint_u32(&tlv, &out->command.add_member.permissions)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

static int parse_publish_key_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv = {0};

    LEDGER_ASSERT(out != NULL, "Null out\n");

    // Read IV
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.publish_key.initialization_vector, IV_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.publish_key.initialization_vector_size = tlv.length;

    // Read encrypted xpriv
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.publish_key.encrypted_xpriv, MAX_ENCRYPTED_KEY_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.publish_key.encrypted_xpriv_size = tlv.length;

    // Read recipient
    if (!tlv_read_next(data, &tlv) || !tlv_read_pubkey(&tlv, out->command.publish_key.recipient)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read ephemeral public key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_generated_pubkey(&tlv, out->command.publish_key.ephemeral_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

/**
 * Read a derivation path from a TLV.
 *
 * @param[in]  tlv     TLV holding the big-endian serialized path.
 * @param[out] out     Destination array.
 * @param[in]  out_len Capacity of @p out, counted in path elements, not in bytes.
 * @return 0 on success, a negative block_parser_error_t otherwise.
 */
static int tlv_read_derivation_path(tlv_t *tlv, uint32_t *out, size_t out_len) {
    LEDGER_ASSERT(tlv != NULL, "Null tlv\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    if (tlv->type != TLV_TYPE_BYTES) {
        return BP_UNEXPECTED_TLV;
    }

    size_t offset = 0;
    size_t index = 0;

    while (offset < tlv->length) {
        if (tlv->length - offset < sizeof(uint32_t)) {
            return BP_UNEXPECTED_TLV;
        }
        if (index >= out_len) {
            return BP_UNEXPECTED_TLV;
        }
        out[index] = read_u32_be(tlv->value, offset);
        index += 1;
        offset += sizeof(uint32_t);
    }
    return 0;
}

static int parse_derive_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv = {0};

    LEDGER_ASSERT(out != NULL, "Null out\n");

    // Read path
    if (!tlv_read_next(data, &tlv) || tlv.type != TLV_TYPE_BYTES || tlv.length == 0 ||
        tlv.length % sizeof(uint32_t) != 0 || tlv.length / sizeof(uint32_t) > MAX_BIP32_PATH) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv_read_derivation_path(&tlv, out->command.derive.path, MAX_BIP32_PATH) != 0) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.derive.path_len = tlv.length / sizeof(uint32_t);

    // Read group key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_generated_pubkey(&tlv, out->command.derive.group_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read IV
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.derive.initialization_vector, IV_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.derive.initialization_vector_size = tlv.length;

    // Read encrypted xpriv
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.derive.encrypted_xpriv, MAX_ENCRYPTED_KEY_LEN)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.derive.encrypted_xpriv_size = tlv.length;

    // Read ephemeral public key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_generated_pubkey(&tlv, out->command.derive.ephemeral_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

int parse_block_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv = {0};

    LEDGER_ASSERT(data != NULL, "Null data\n");
    LEDGER_ASSERT(out != NULL, "Null out\n");

    size_t offset = data->offset;
    int read = 0;

    if (!tlv_read_next(data, &tlv)) {
        PRINTF("Cannot read command TLV\n");
        return -1;
    }

    buffer_t commandBuffer = {.ptr = (uint8_t *) tlv.value, .offset = 0, .size = tlv.length};

    out->type = (block_command_type_e) tlv.type;
    switch (tlv.type) {
        case COMMAND_SEED:
            read = parse_seed_command(&commandBuffer, out);
            break;
        case COMMAND_ADD_MEMBER:
            read = parse_add_member_command(&commandBuffer, out);
            break;
        case COMMAND_PUBLISH_KEY:
            read = parse_publish_key_command(&commandBuffer, out);
            break;
        case COMMAND_DERIVE:
            read = parse_derive_command(&commandBuffer, out);
            break;
        case COMMAND_CLOSE_STREAM:
            // The hasher emits this command with an empty value, so only an empty value can be
            // covered by the signature
            if (tlv.length != 0) {
                return BP_UNEXPECTED_TLV;
            }
            read = 0;
            PRINTF("Close stream command\n");
            break;
        default:
            return BP_ERROR_UNKNOWN_COMMAND;
            break;
    }
    if (read < 0) {
        return read;
    }
    // Bytes left inside the command are absent from the digest the signature covers
    if (commandBuffer.offset != commandBuffer.size) {
        PRINTF("Trailing bytes in command\n");
        return BP_UNEXPECTED_TLV;
    }
    return data->offset - offset;
}

int parse_block_signature(buffer_t *data, uint8_t *out, size_t out_len) {
    tlv_t tlv = {0};
    int status;

    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }

    if (tlv.length > MAX_DER_SIG_LEN) {
        return BP_OVERSIZED_FIELD;
    }

    status = tlv_read_signature(&tlv, out, out_len) ? 0 : BP_UNEXPECTED_TLV;
    return status >= 0 ? tlv.length : status;
}
