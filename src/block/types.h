#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "bip32.h"
#include "../constants.h"
#include "../crypto.h"

typedef struct {
    uint8_t version;                 // Protocol version of the block
    uint8_t parent[HASH_LEN];        // Hash of the parent block
    uint8_t issuer[MEMBER_KEY_LEN];  // Issuer of the block
    uint8_t length;                  // Number of instruction in the block
} block_header_t;

typedef enum {
    COMMAND_SEED = 0x10,
    COMMAND_ADD_MEMBER = 0x11,
    COMMAND_PUBLISH_KEY = 0x12,
    COMMAND_EDIT_MEMBER = 0x14,
    COMMAND_DERIVE = 0x15,
    COMMAND_CLOSE_STREAM = 0x13
} block_command_type_e;

typedef enum {
    KEY_READER = 0x01,
    KEY_CREATOR = 0x02,
    KEY_REVOKER = 0x04,
    ADD_MEMBER = 0x08,
    REMOVE_MEMBER = 0x16,
    CHANGE_MEMBER_PERMISSIONS = 0x32,
    CHANGE_MEMBER_NAME = 0x64,

    OWNER = (int) 0xFFFFFFFF,
} member_permission_t;

typedef struct {
    uint8_t topic[MAX_TOPIC_LEN];
    uint8_t topic_len;
    uint16_t protocol_version;
    uint8_t group_public_key[MEMBER_KEY_LEN];
    uint8_t initialization_vector[IV_LEN];
    uint8_t encrypted_xpriv_size;
    uint8_t encrypted_xpriv[MAX_ENCRYPTED_KEY_LEN];
    uint8_t ephemeral_public_key[MEMBER_KEY_LEN];
} block_command_seed_t;

typedef struct {
    uint32_t path[MAX_BIP32_PATH];
    uint8_t path_len;
    uint8_t group_public_key[MEMBER_KEY_LEN];
    uint8_t initialization_vector[IV_LEN];
    uint8_t encrypted_xpriv_size;
    uint8_t encrypted_xpriv[MAX_ENCRYPTED_KEY_LEN];
    uint8_t ephemeral_public_key[MEMBER_KEY_LEN];
} block_command_derive_t;

typedef struct {
    uint8_t public_key[MEMBER_KEY_LEN];
    uint32_t permissions;
    char name[MAX_NAME_LEN + 1];
} block_command_add_member_t;

typedef struct {
    uint8_t initialization_vector[IV_LEN];
    uint8_t encrypted_xpriv[MAX_ENCRYPTED_KEY_LEN];
    uint8_t encrypted_xpriv_size;
    uint8_t recipient[MEMBER_KEY_LEN];
    uint8_t ephemeral_public_key[MEMBER_KEY_LEN];
} block_command_publish_key_t;

typedef struct {
    block_command_type_e type;
    union {
        block_command_seed_t seed;
        block_command_derive_t derive;
        block_command_add_member_t add_member;
        block_command_publish_key_t publish_key;
    } command;
} block_command_t;

typedef struct {
    crypto_hash_t digest;                // Current block digest
    uint8_t signature[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t signature_len;               /// length of transaction signature
    uint8_t v;                           /// parity of y-coordinate of R in ECDSA signature

    uint8_t command_count;   // Number of commands in the block to sign
    uint8_t parsed_command;  // Number of commands parsed

    uint8_t session_key[MEMBER_KEY_LEN];  // Session key (ephemeral public key)
    uint8_t session_encryption_key[SESSION_ENCRYPTION_KEY_LEN];
} signer_ctx_t;