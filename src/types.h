#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "constants.h"
#include "bip32.h"

#include "stream/stream.h"
#include "block/signer.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,   /// version of the application
    GET_APP_NAME = 0x04,  /// name of the application
    GET_SEED_ID = 0x05,   /// get public key NOT IMPLEMENTED
    INIT = 0x06,  /// Initialize secure flows (block signature, GET SeedID, AUTHENTICATE w/ SeedID)
    SIGN_BLOCK = 0x07,          /// sign block of a parsed stream
    PARSE_STREAM = 0x08,        /// parse a stream
    SET_TRUSTED_MEMBER = 0x09,  /// set a trusted member for upcoming commands
} command_e;

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,      /// confirm address derived from public key
    CONFIRM_TRANSACTION,  /// confirm transaction information
    CONFIRM_BLOCK         /// confirm block signature
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[RAW_PUBLIC_KEY_LENGTH];  /// x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[MEMBER_KEY_LEN];             /// for public key derivation
    uint8_t compressed_pk[MEMBER_KEY_LEN];          /// compressed public key
} pubkey_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;      /// public key context
        signer_ctx_t signer_info;  /// signer context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// length of BIP32 path

    stream_ctx_t stream;  /// Stream context
} global_ctx_t;
