#include "block_hasher.h"
#include "write.h"
#include "../common/tlv.h"
#include <string.h>
#include "bip32.h"

#define TLV_HEADER_LEN 2

static int write_tl(const uint8_t type, const uint8_t length, uint8_t *out) {
    LEDGER_ASSERT(out != NULL, "Null pointer");
    out[0] = type;
    out[1] = length;
    return TLV_HEADER_LEN;
}

static void write_command_seed(const block_command_t *command, crypto_hash_t *digest) {
    uint8_t buffer[MAX_TOPIC_LEN + 2 + MEMBER_KEY_LEN + IV_LEN + MAX_ENCRYPTED_KEY_LEN +
                   MEMBER_KEY_LEN + TLV_HEADER_LEN * 6 + TLV_HEADER_LEN];
    int offset = 0;

    LEDGER_ASSERT(digest != NULL, "Null pointer");
    LEDGER_ASSERT(command != NULL, "Null pointer");
    LEDGER_ASSERT(command->command.seed.topic_len <= MAX_TOPIC_LEN, "Wrong length");

    // Compute encoded data length
    // Topic(16 max) + ProtocolVersion(2) + GroupKey(33) + IV(16) + EncryptedSeed(64) +
    // EphemeralPublicKey(33) + 2 * NumberOfFields
    uint8_t length = command->command.seed.topic_len + 2 + MEMBER_KEY_LEN + IV_LEN +
                     MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN + TLV_HEADER_LEN * 6;

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // Topic
    offset += write_tl(TLV_TYPE_BYTES, command->command.seed.topic_len, buffer + offset);
    memcpy(buffer + offset, command->command.seed.topic, command->command.seed.topic_len);
    offset += command->command.seed.topic_len;

    // Protocol version
    offset += write_tl(TLV_TYPE_VARINT, 2, buffer + offset);
    write_u16_be(buffer, offset, command->command.seed.protocol_version);
    offset += sizeof(uint16_t);

    // Group key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.seed.group_public_key, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    // IV
    offset += write_tl(TLV_TYPE_BYTES,
                       sizeof(command->command.seed.initialization_vector),
                       buffer + offset);
    memcpy(buffer + offset,
           command->command.seed.initialization_vector,
           sizeof(command->command.seed.initialization_vector));
    offset += sizeof(command->command.seed.initialization_vector);

    // Encrypted xpriv
    offset +=
        write_tl(TLV_TYPE_BYTES, sizeof(command->command.seed.encrypted_xpriv), buffer + offset);
    memcpy(buffer + offset,
           command->command.seed.encrypted_xpriv,
           sizeof(command->command.seed.encrypted_xpriv));
    offset += sizeof(command->command.seed.encrypted_xpriv);

    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.seed.ephemeral_public_key, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    crypto_digest_update(digest, buffer, offset);
}

static void write_command_derive(const block_command_t *command, crypto_hash_t *digest) {
    uint8_t buffer[MAX_BIP32_PATH * sizeof(uint32_t) + MEMBER_KEY_LEN + IV_LEN +
                   MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN + TLV_HEADER_LEN * 5 + TLV_HEADER_LEN];
    int offset = 0;

    LEDGER_ASSERT(digest != NULL, "Null pointer");
    LEDGER_ASSERT(command != NULL, "Null pointer");
    LEDGER_ASSERT(command->command.derive.path_len <= MAX_BIP32_PATH, "Wrong length");

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
        write_u32_be(buffer, offset, command->command.derive.path[i]);
        offset += sizeof(uint32_t);
    }

    // Group key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.derive.group_public_key, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    // IV
    offset += write_tl(TLV_TYPE_BYTES,
                       sizeof(command->command.derive.initialization_vector),
                       buffer + offset);
    memcpy(buffer + offset,
           command->command.derive.initialization_vector,
           sizeof(command->command.derive.initialization_vector));
    offset += sizeof(command->command.derive.initialization_vector);

    // Encrypted xpriv
    offset +=
        write_tl(TLV_TYPE_BYTES, sizeof(command->command.derive.encrypted_xpriv), buffer + offset);
    memcpy(buffer + offset,
           command->command.derive.encrypted_xpriv,
           sizeof(command->command.derive.encrypted_xpriv));
    offset += sizeof(command->command.derive.encrypted_xpriv);

    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset,
           command->command.derive.ephemeral_public_key,
           sizeof(command->command.derive.ephemeral_public_key));
    offset += sizeof(command->command.derive.ephemeral_public_key);

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

    LEDGER_ASSERT(command != NULL, "Null pointer");
    LEDGER_ASSERT(digest != NULL, "Null pointer");

    LEDGER_ASSERT(name_len <= MAX_NAME_LEN, "Wrong name length");

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // Name
    offset += write_tl(TLV_TYPE_STRING, name_len, buffer + offset);
    memcpy(buffer + offset, command->command.add_member.name, name_len);
    offset += name_len;

    // Public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.add_member.public_key, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    // Permissions
    offset += write_tl(TLV_TYPE_VARINT, sizeof(uint32_t), buffer + offset);
    write_u32_be(buffer, offset, command->command.add_member.permissions);
    offset += sizeof(uint32_t);

    crypto_digest_update(digest, buffer, offset);
}

static void write_command_publish_key(const block_command_t *command, crypto_hash_t *digest) {
    int offset = 0;
    uint8_t buffer[TLV_HEADER_LEN + IV_LEN + MAX_ENCRYPTED_KEY_LEN + MEMBER_KEY_LEN +
                   MEMBER_KEY_LEN + 4 * TLV_HEADER_LEN];

    // Compute encoded data length
    uint8_t length = sizeof(buffer) - TLV_HEADER_LEN;

    LEDGER_ASSERT(command != NULL, "Null pointer");
    LEDGER_ASSERT(digest != NULL, "Null pointer");

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // IV
    offset += write_tl(TLV_TYPE_BYTES, IV_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.publish_key.initialization_vector, IV_LEN);
    offset += IV_LEN;

    // Encrypted xpriv
    offset += write_tl(TLV_TYPE_BYTES, MAX_ENCRYPTED_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.publish_key.encrypted_xpriv, MAX_ENCRYPTED_KEY_LEN);
    offset += MAX_ENCRYPTED_KEY_LEN;

    // Recipient public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.publish_key.recipient, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, command->command.publish_key.ephemeral_public_key, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    crypto_digest_update(digest, buffer, offset);
}

static void write_command_close_stream(const block_command_t *command, crypto_hash_t *digest) {
    uint8_t buffer[TLV_HEADER_LEN];

    LEDGER_ASSERT(command != NULL, "Null pointer");
    LEDGER_ASSERT(digest != NULL, "Null pointer");

    // Command type and length
    write_tl(command->type, 0, buffer);

    crypto_digest_update(digest, buffer, TLV_HEADER_LEN);
}

void block_hash_header(const block_header_t *header, crypto_hash_t *digest) {
    uint8_t buffer[1 + HASH_LEN + MEMBER_KEY_LEN + 1 + 4 * TLV_HEADER_LEN];
    int offset = 0;

    LEDGER_ASSERT(header != NULL, "Null pointer");
    LEDGER_ASSERT(digest != NULL, "Null pointer");

    // Version
    offset += write_tl(TLV_TYPE_VARINT, sizeof(header->version), buffer + offset);
    buffer[offset] = header->version;
    offset += sizeof(header->version);

    // Parent
    offset += write_tl(TLV_TYPE_HASH, HASH_LEN, buffer + offset);
    memcpy(buffer + offset, header->parent, HASH_LEN);
    offset += HASH_LEN;

    // Issuer
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    memcpy(buffer + offset, header->issuer, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    // Length
    offset += write_tl(TLV_TYPE_VARINT, 1, buffer + offset);
    buffer[offset] = header->length;
    offset += sizeof(header->length);

    crypto_digest_update(digest, buffer, offset);
}

int block_hash_command(const block_command_t *command, crypto_hash_t *digest) {
    LEDGER_ASSERT(command != NULL, "Null pointer");

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
    return 0;
}

void block_hash_signature(const uint8_t *signature, size_t signature_len, crypto_hash_t *digest) {
    uint8_t buffer[TLV_HEADER_LEN + MAX_DER_SIG_LEN];
    int offset = 0;

    LEDGER_ASSERT(signature != NULL, "Null pointer");
    LEDGER_ASSERT(digest != NULL, "Null pointer");

    LEDGER_ASSERT(TLV_HEADER_LEN + signature_len <= TLV_HEADER_LEN + MAX_DER_SIG_LEN,
                  "Wrong length");

    // Signature
    offset += write_tl(TLV_TYPE_SIG, signature_len, buffer + offset);
    memcpy(buffer + offset, signature, signature_len);
    offset += signature_len;
    crypto_digest_update(digest, buffer, offset);
}