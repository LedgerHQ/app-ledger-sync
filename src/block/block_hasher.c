#include "block_hasher.h"
#include "write.h"
#include "../common/tlv.h"
#include <string.h>

#define TLV_HEADER_LEN 2

static int write_tl(const uint8_t type, const uint8_t length, uint8_t *out) {
    out[0] = type;
    out[1] = length;
    return 2;
}

static int write_u8(const uint8_t value, uint8_t *out) {
    out[0] = value;
    return sizeof(value);
}

static int write_u16(const uint16_t value, uint8_t *out) {
    out[0] = (value >> 8) & 0xFF;
    out[1] = value & 0xFF;
    return sizeof(value);
}

static int write_u32(const uint32_t value, uint8_t *out) {
    out[0] = (value >> 24) & 0xFF;
    out[1] = (value >> 16) & 0xFF;
    out[2] = (value >> 8) & 0xFF;
    out[3] = value & 0xFF;
    return sizeof(value);
}

static int write_bytes(const uint8_t *bytes, const uint8_t length, uint8_t *out) {
    for (int i = 0; i < length; i++) {
        out[i] = bytes[i];
    }
    return length;
}

static void write_command_seed(const block_command_t *command, crypto_hash_t *digest) {
    uint8_t buffer[MAX_TOPIC_LEN + 2 + MEMBER_KEY_LEN + IV_LEN + MAX_ENCRYPTED_KEY_LEN +
                   MEMBER_KEY_LEN + TLV_HEADER_LEN * 6 + TLV_HEADER_LEN];
    int offset = 0;

    // Compute encoded data length
    // Topic(16 max) + ProtocolVersion(2) + GroupKey(33) + IV(16) + EncryptedSeed(64) +
    // EphemeralPublicKey(33) + 2 * NumberOfFields
    uint8_t length = command->command.seed.topic_len + 2 + MEMBER_KEY_LEN + IV_LEN +
                     MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN + 2 * 6;

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // Topic
    offset += write_tl(TLV_TYPE_BYTES, command->command.seed.topic_len, buffer + offset);
    offset +=
        write_bytes(command->command.seed.topic, command->command.seed.topic_len, buffer + offset);

    // Protocol version
    offset += write_tl(TLV_TYPE_VARINT, 2, buffer + offset);
    offset += write_u16(command->command.seed.protocol_version, buffer + offset);

    // Group key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.seed.group_public_key, MEMBER_KEY_LEN, buffer + offset);

    // IV
    offset += write_tl(TLV_TYPE_BYTES,
                       sizeof(command->command.seed.initialization_vector),
                       buffer + offset);
    offset += write_bytes(command->command.seed.initialization_vector,
                          sizeof(command->command.seed.initialization_vector),
                          buffer + offset);

    // Encrypted xpriv
    offset +=
        write_tl(TLV_TYPE_BYTES, sizeof(command->command.seed.encrypted_xpriv), buffer + offset);
    offset += write_bytes(command->command.seed.encrypted_xpriv,
                          sizeof(command->command.seed.encrypted_xpriv),
                          buffer + offset);

    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset +=
        write_bytes(command->command.seed.ephemeral_public_key, MEMBER_KEY_LEN, buffer + offset);

    buffer[1] =
        offset - 2;  // Set actual length (offset - 2 because offset includes type and length bytes)
    crypto_digest_update(digest, buffer, offset);
}

static void write_command_derive(const block_command_t *command, crypto_hash_t *digest) {
    uint8_t buffer[MAX_DERIVATION_PATH_LEN * sizeof(uint32_t) + MEMBER_KEY_LEN + IV_LEN +
                   MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN + TLV_HEADER_LEN * 5 + TLV_HEADER_LEN];
    int offset = 0;

    // Compute encoded data length
    // Path(max 40) + GroupKey(33) + IV(16) + EncryptedXpriv(64) + EphemeralPublicKey(33) + 2 *
    // NumberOfFields
    uint8_t length = command->command.derive.path_len * sizeof(uint32_t) + MEMBER_KEY_LEN + IV_LEN +
                     MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN + TLV_HEADER_LEN * 5;

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // Path
    offset += write_tl(TLV_TYPE_BYTES,
                       command->command.derive.path_len * sizeof(uint32_t),
                       buffer + offset);
    for (int i = 0; i < command->command.derive.path_len; i++) {
        offset += write_u32(command->command.derive.path[i], buffer + offset);
    }

    // Group key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset +=
        write_bytes(command->command.derive.group_public_key, MEMBER_KEY_LEN, buffer + offset);

    // IV
    offset += write_tl(TLV_TYPE_BYTES,
                       sizeof(command->command.derive.initialization_vector),
                       buffer + offset);
    offset += write_bytes(command->command.derive.initialization_vector,
                          sizeof(command->command.derive.initialization_vector),
                          buffer + offset);

    // Encrypted xpriv
    offset +=
        write_tl(TLV_TYPE_BYTES, sizeof(command->command.derive.encrypted_xpriv), buffer + offset);
    offset += write_bytes(command->command.derive.encrypted_xpriv,
                          sizeof(command->command.derive.encrypted_xpriv),
                          buffer + offset);

    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset +=
        write_bytes(command->command.derive.ephemeral_public_key, MEMBER_KEY_LEN, buffer + offset);

    crypto_digest_update(digest, buffer, offset);
}

static void write_command_add_member(const block_command_t *command, crypto_hash_t *digest) {
    int offset = 0;
    uint8_t buffer[MAX_NAME_LEN + MEMBER_KEY_LEN + sizeof(uint32_t) + 3 * TLV_HEADER_LEN +
                   TLV_HEADER_LEN];
    int name_len = strlen(command->command.add_member.name);

    // Compute encoded data length
    // Name(max 100) + PublicKey(33) + Permissions(4)
    uint8_t length = name_len + MEMBER_KEY_LEN + sizeof(uint32_t) + 3 * TLV_HEADER_LEN;

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // Name
    offset += write_tl(TLV_TYPE_STRING, name_len, buffer + offset);
    offset += write_bytes((uint8_t *) command->command.add_member.name, name_len, buffer + offset);

    // Public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.add_member.public_key, MEMBER_KEY_LEN, buffer + offset);

    // Permissions
    offset += write_tl(TLV_TYPE_VARINT, sizeof(uint32_t), buffer + offset);
    offset += write_u32(command->command.add_member.permissions, buffer + offset);

    crypto_digest_update(digest, buffer, offset);
}

// static void write_command_edit_member(const block_command_t *command, crypto_hash_t *digest) {
//     // NOT IMPLEMENTED
//     (void) command;
//     (void) digest;
// }

static void write_command_publish_key(const block_command_t *command, crypto_hash_t *digest) {
    int offset = 0;
    uint8_t buffer[TLV_HEADER_LEN + IV_LEN + MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN +
                   MEMBER_KEY_LEN + 4 * TLV_HEADER_LEN];

    // Compute encoded data length
    uint8_t length = sizeof(buffer) - TLV_HEADER_LEN;

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // IV
    offset += write_tl(TLV_TYPE_BYTES, IV_LEN, buffer + offset);
    offset +=
        write_bytes(command->command.publish_key.initialization_vector, IV_LEN, buffer + offset);

    // Encrypted xpriv
    offset += write_tl(TLV_TYPE_BYTES, MAX_ENCRYPTED_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.publish_key.encrypted_xpriv,
                          MAX_ENCRYPTED_KEY_LEN,
                          buffer + offset);

    // Recipient public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.publish_key.recipient, MEMBER_KEY_LEN, buffer + offset);

    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.publish_key.ephemeral_public_key,
                          MEMBER_KEY_LEN,
                          buffer + offset);

    crypto_digest_update(digest, buffer, offset);
}

static void write_command_close_stream(const block_command_t *command, crypto_hash_t *digest) {
    uint8_t buffer[TLV_HEADER_LEN];

    // Command type and length
    write_tl(command->type, 0, buffer);

    crypto_digest_update(digest, buffer, TLV_HEADER_LEN);
}

int block_hash_header(const block_header_t *header, crypto_hash_t *digest) {
    int ret = 0;
    uint8_t buffer[1 + HASH_LEN + MEMBER_KEY_LEN + 1 + 4 * 2];
    int offset = 0;

    // Version
    offset += write_tl(TLV_TYPE_VARINT, 1, buffer + offset);
    offset += write_u8(header->version, buffer + offset);

    // Parent
    offset += write_tl(TLV_TYPE_HASH, HASH_LEN, buffer + offset);
    offset += write_bytes(header->parent, HASH_LEN, buffer + offset);

    // Issuer
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(header->issuer, MEMBER_KEY_LEN, buffer + offset);

    // Length
    offset += write_tl(TLV_TYPE_VARINT, 1, buffer + offset);
    offset += write_u8(header->length, buffer + offset);
    BEGIN_TRY {
        TRY {
            crypto_digest_update(digest, buffer, offset);
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    return ret;
}

int block_hash_command(const block_command_t *command, crypto_hash_t *digest) {
    int ret = 0;
    BEGIN_TRY {
        TRY {
            switch (command->type) {
                case COMMAND_SEED:
                    write_command_seed(command, digest);
                    break;
                case COMMAND_ADD_MEMBER:
                    write_command_add_member(command, digest);
                    break;
                case COMMAND_DERIVE:
                    write_command_derive(command, digest);
                    break;
                case COMMAND_CLOSE_STREAM:
                    write_command_close_stream(command, digest);
                    break;
                case COMMAND_PUBLISH_KEY:
                    write_command_publish_key(command, digest);
                    break;
                default:
                    return BP_ERROR_UNKNOWN_COMMAND;
            }
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    return ret;
}

int block_hash_signature(const uint8_t *signature, size_t signature_len, crypto_hash_t *digest) {
    int ret = 0;
    uint8_t buffer[TLV_HEADER_LEN + MAX_DER_SIG_LEN];
    int offset = 0;

    // Signature
    offset += write_tl(TLV_TYPE_SIG, signature_len, buffer + offset);
    offset += write_bytes(signature, signature_len, buffer + offset);
    BEGIN_TRY {
        TRY {
            crypto_digest_update(digest, buffer, offset);
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    return ret;
}