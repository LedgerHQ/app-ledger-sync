#include "block_parser.h"
#include "../common/tlv.h"
#include "read.h"
#include "bip32.h"

int parse_block_header(buffer_t *data, block_header_t *out) {
    tlv_t tlv;
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
    tlv_t tlv;

    // Read the topic
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MAX_TOPIC_LEN) {
        return BP_OVERSIZED_FIELD;
    }
    out->command.seed.topic_len = tlv.length;
    tlv_read_bytes(&tlv, out->command.seed.topic, MAX_TOPIC_LEN);

    // Read protocol version

    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_varint_u16(&tlv, &out->command.seed.protocol_version)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read group public key
    if (!tlv_read_next(data, &tlv) || !tlv_read_pubkey(&tlv, out->command.seed.group_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read IV
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.seed.initialization_vector, IV_LEN)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read encrypted xpriv
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.seed.encrypted_xpriv, MAX_ENCRYPTED_KEY_LEN)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read ephemeral public key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_pubkey(&tlv, out->command.seed.ephemeral_public_key))
        return BP_UNEXPECTED_TLV;

    return 0;
}

static int parse_add_member_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;

    // Read member name
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MAX_NAME_LEN) {
        return BP_OVERSIZED_FIELD;
    }

    tlv_read_string(&tlv, out->command.add_member.name, sizeof(out->command.add_member.name));

    // Read member public key
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MEMBER_KEY_LEN) {
        return BP_OVERSIZED_FIELD;
    }
    tlv_read_pubkey(&tlv, out->command.add_member.public_key);

    // Read member permissions
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_varint_u32(&tlv, &out->command.add_member.permissions)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

static int parse_publish_key_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;

    // Read IV
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.publish_key.initialization_vector, IV_LEN)) {
        return BP_UNEXPECTED_TLV;
    }

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
        !tlv_read_pubkey(&tlv, out->command.publish_key.ephemeral_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

static int tlv_read_derivation_path(tlv_t *tlv, uint32_t *out, int out_len) {
    if (tlv->type != TLV_TYPE_BYTES) {
        return BP_UNEXPECTED_TLV;
    }
    int offset = 0;
    int index = 0;
    while (offset < tlv->length) {
        if (tlv->length - offset < (int) sizeof(uint32_t)) {
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
    tlv_t tlv;

    // Read path
    if (!tlv_read_next(data, &tlv) ||
        tlv_read_derivation_path(&tlv,
                                 out->command.derive.path,
                                 sizeof(out->command.derive.path)) != 0) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.derive.path_len = tlv.length / sizeof(uint32_t);
    if (tlv.length % sizeof(uint32_t) != 0) {
        return BP_UNEXPECTED_TLV;
    }

    // Read group key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_pubkey(&tlv, out->command.derive.group_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read IV
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.derive.initialization_vector, IV_LEN)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read encrypted xpriv
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.derive.encrypted_xpriv, MAX_ENCRYPTED_KEY_LEN)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read ephemeral public key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_pubkey(&tlv, out->command.derive.ephemeral_public_key)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

int parse_block_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;
    size_t offset = data->offset;
    int read = 0;

    if (!tlv_read_next(data, &tlv)) {
        PRINTF("Cannot read command TLV\n");
        return -1;
    }

    buffer_t commandBuffer = {.ptr = tlv.value, .offset = 0, .size = tlv.length};

    out->type = tlv.type;
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
            read = tlv.length;
            PRINTF("Close stream command\n");
            break;
        default:
            PRINTF("Close stream command\n");
            return BP_ERROR_UNKNOWN_COMMAND;
            break;
    }
    return read < 0 ? read : data->offset - offset;
}

int parse_block_signature(buffer_t *data, uint8_t *out, size_t out_len) {
    tlv_t tlv;
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