#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

/**
 * Protocol is TLV
 */
#define TAG_LABEL_OFFSET 0
#define LENGTH_OFFSET    1
#define VALUE_OFFSET     2

/**
 * Field Length for challenge data
 */
#define PROTOCOL_LENGTH         4
#define CHALLENGE_DATA_LENGTH   16
#define CHALLENGE_EXPIRY_LENGTH 4
#define HOST_LENGTH             64
#define PUBLIC_KEY_LENGTH       33
#define SIGNATURE_LENGTH        75

/**
 * Enumeration labels
 */
typedef enum {
    STRUCTURE_TYPE = 0x01,
    VERSION = 0x02,
    CHALLENGE = 0x12,
    SIGNER_ALGO = 0x14,
    DER_SIGNATURE = 0x15,
    VALID_UNTIL = 0x16,
    TRUSTED_NAME = 0x20,
    PUBLIC_KEY_CURVE = 0x32,
    PUBLIC_KEY = 0x33,
    PROTOCOL_VERSION = 0x60,
} challenge_label_e;

/**
 * Challenge structure type
 */
typedef struct {
    uint8_t payload_type;
    uint8_t version;
    uint8_t protocol_version[PROTOCOL_LENGTH];
    uint8_t challenge_data[CHALLENGE_DATA_LENGTH];
    uint8_t challenge_expiry[CHALLENGE_EXPIRY_LENGTH];
    uint8_t host[HOST_LENGTH];
    uint8_t rp_credential_sign_algorithm;
    uint8_t rp_credential_curve_id;
    uint8_t rp_credential_public_key[PUBLIC_KEY_LENGTH];
    uint8_t rp_signature[SIGNATURE_LENGTH];
} challenge_ctx_t;

typedef struct {
    uint8_t version;
    uint8_t curve_ID;
    uint8_t sign_algorithm;
    uint8_t public_key_length;
    uint8_t public_key[PUBLIC_KEY_LENGTH];
} pubkey_credential_t;

/**
 * Supported values:
 */
#define ECDSA_SHA256 0x01

#define SEED_ID_PROTOCOL_VERSION_M       0x01
#define SEED_ID_PROTOCOL_VERSION_N       0x00
#define SEED_ID_PROTOCOL_VERSION_P_UPPER 0x00
#define SEED_ID_PROTOCOL_VERSION_P_LOWER 0x00

#define SEED_ID_VERSION                          0x00
#define TYPE_SEED_ID__AUTHENTIFICATION_CHALLENGE 0x07
#define SEED_ID_PUBKEY_VERSION                   0x00
#define SEED_ID_CURVE_ID                         CX_CURVE_256K1
#define SEED_ID_SIGN_ALGORTITHM                  ECDSA_SHA256

/**
 * Parser for challenge data
 */
int challenge_parse_buffer(buffer_t* buffer,
                           challenge_ctx_t* challenge_ctx,
                           uint8_t* challenge_hash);
