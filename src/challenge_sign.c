#include "challenge_sign.h"
#include "challenge_parser.h"
#include "io.h"
#include "sw.h"
#include "globals.h"
#include "crypto_helpers.h"
#include "crypto_data.h"
#ifdef HAVE_LEDGER_PKI
#include "os_pki.h"
#endif

// Response contains:
// - pubkey_credential_t (72 Bytes)
// - pubkey_signature_len (1 Byte)
// - pubkey_signature (max MAX_DER_SIG_LEN Bytes)
// - Attestation ID (1 Byte)
// - pubkey_credential_t (72 Bytes)
// - attestation_signature_len (1 Byte)
// - attestation_signature (max MAX_DER_SIG_LEN Bytes)
#define MAX_CHALLENGE_RESP_SIZE ((2 * (sizeof(pubkey_credential_t) + MAX_DER_SIG_LEN)) + 3)

static int send_challenge(uint8_t* compressed_seed_id_public_key,
                          uint8_t* signature,
                          size_t signature_len,
                          uint8_t* attestation_pubkey,
                          uint8_t* attestation_signature,
                          size_t attestation_signature_len) {
    // Return SeedID public key + SeedID signature + Attestion PublicKey

    static uint8_t resp[MAX_CHALLENGE_RESP_SIZE] = {0};
    LEDGER_ASSERT(compressed_seed_id_public_key != NULL, "Null pointer");
    LEDGER_ASSERT(signature != NULL, "Null pointer");
    LEDGER_ASSERT(attestation_signature != NULL, "Null pointer");

    LEDGER_ASSERT(signature_len <= MAX_DER_SIG_LEN, "Null pointer");
    LEDGER_ASSERT(attestation_signature_len <= MAX_DER_SIG_LEN, "Null pointer");

    size_t offset = 0;

    // PubKey
    resp[offset++] = SEED_ID_PUBKEY_VERSION;
    resp[offset++] = SEED_ID_CURVE_ID;
    resp[offset++] = SEED_ID_SIGN_ALGORTITHM;
    resp[offset++] = PUBLIC_KEY_LENGTH;

    memcpy(resp + offset, compressed_seed_id_public_key, PUBLIC_KEY_LENGTH);
    offset += PUBLIC_KEY_LENGTH;

    // SeedID signature
    resp[offset++] = signature_len;
    memcpy(resp + offset, signature, signature_len);
    offset += signature_len;

    // Attestation
    resp[offset++] = APPLICATION_ATTESTATION;

    // PubKey
    resp[offset++] = SEED_ID_PUBKEY_VERSION;
    resp[offset++] = SEED_ID_CURVE_ID;
    resp[offset++] = SEED_ID_SIGN_ALGORTITHM;
    resp[offset++] = PUBLIC_KEY_LENGTH;

    memcpy(resp + offset, attestation_pubkey, PUBLIC_KEY_LENGTH);
    offset += PUBLIC_KEY_LENGTH;

    // Attestation signature
    resp[offset++] = attestation_signature_len;
    memcpy(resp + offset, attestation_signature, attestation_signature_len);
    offset += attestation_signature_len;

    return io_send_response_pointer(resp, offset, SW_OK);
}

static int sign_attestion(uint8_t* attestation,
                          uint8_t* attestation_signature,
                          size_t* attestation_signature_len) {
    cx_ecfp_private_key_t attestation_private_key;
    int error = 0;

    LEDGER_ASSERT(attestation != NULL, "Null pointer");
    LEDGER_ASSERT(attestation_signature != NULL, "Null pointer");
    LEDGER_ASSERT(attestation_signature_len != NULL, "Null pointer");

    if (cx_ecfp_init_private_key_no_throw(SEED_ID_CURVE_ID,
                                          ATTESTATION_KEY,
                                          32,
                                          &attestation_private_key) != CX_OK) {
        return SW_SIGNATURE_FAIL;
    }

    if (cx_ecdsa_sign_no_throw(&attestation_private_key,
                               CX_RND_RFC6979 | CX_LAST,
                               CX_SHA256,
                               attestation,
                               CX_SHA256_SIZE,
                               attestation_signature,
                               attestation_signature_len,
                               NULL) != CX_OK) {
        PRINTF("ERROR Signing Attestation\n");
        error = SW_SIGNATURE_FAIL;
    }

    explicit_bzero(&attestation_private_key, sizeof(cx_ecfp_private_key_t));
    return error;
}

static int get_public_key(uint8_t* compressed_public_key) {
    uint8_t raw_pubkey[RAW_PUBLIC_KEY_LENGTH + 1];

    if (bip32_derive_get_pubkey_256(SEED_ID_CURVE_ID,
                                    SEED_ID_PATH,
                                    SEED_ID_PATH_LEN,
                                    raw_pubkey,
                                    NULL,
                                    CX_SHA256) != CX_OK) {
        return SW_SIGNATURE_FAIL;
    }

    crypto_compress_public_key(raw_pubkey, compressed_public_key);
    return 0;
}

int verify_challenge_signature(challenge_ctx_t* challenge_ctx, uint8_t* challenge_hash) {
#ifdef HAVE_LEDGER_PKI
    cx_err_t error = CX_INTERNAL_ERROR;
    uint8_t key_usage = 0;
    size_t trusted_name_len = 0;
    uint8_t trusted_name[CERTIFICATE_TRUSTED_NAME_MAXLEN] = {0};
    cx_ecfp_384_public_key_t public_key = {0};
    uint8_t comp_key[PUBLIC_KEY_LENGTH];
#endif

    if (!challenge_ctx) {
        PRINTF("Null pointer");
        return SW_CHALLENGE_NOT_VERIFIED;
    }
    if (challenge_ctx->payload_type != TYPE_SEED_ID_AUTHENTIFICATION_CHALLENGE) {
        PRINTF("Wrong payload type");
        return SW_CHALLENGE_NOT_VERIFIED;
    }

    PRINTF("Verifying challenge signature\n");

    PRINTF("==================================================================================\n");
#ifdef HAVE_LEDGER_PKI
    error = os_pki_get_info(&key_usage, trusted_name, &trusted_name_len, &public_key);
    if ((error == 0) && (key_usage == CERTIFICATE_PUBLIC_KEY_USAGE_SEED_ID_AUTH) &&
        (public_key.curve == CX_CURVE_SECP256K1)) {
        PRINTF("Certificate '%s' loaded for usage 'SEED_ID'\n", trusted_name);

        if (strncmp((const char*) challenge_ctx->host,
                    (const char*) trusted_name,
                    CERTIFICATE_TRUSTED_NAME_MAXLEN) != 0) {
            PRINTF("Signature not verified!\n");
            return SW_CHALLENGE_NOT_VERIFIED;
        }

        crypto_compress_public_key(public_key.W, (uint8_t*) &comp_key);
        // Check the key received is authenticated
        if (memcmp(challenge_ctx->rp_credential_public_key, comp_key, PUBLIC_KEY_LENGTH) != 0) {
            PRINTF("Signature not verified!\n");
            return SW_CHALLENGE_NOT_VERIFIED;
        }
    } else
#endif
    {
        PRINTF("********** No certificate loaded. Using legacy path **********\n");
    }

    uint8_t sig_len = challenge_ctx->rp_signature[1] + 2;
    int verified = crypto_verify_signature(challenge_ctx->rp_credential_public_key,
                                           challenge_hash,
                                           challenge_ctx->rp_signature,
                                           sig_len);

    if (verified != CX_OK) {
        PRINTF("Signature not verified %d \n", verified);
        return SW_CHALLENGE_NOT_VERIFIED;
    }
    PRINTF("Signature verified\n");

    return 0;
}

int sign_challenge(uint8_t* challenge_hash) {
    uint8_t signature[MAX_DER_SIG_LEN];
    size_t signature_len = MAX_DER_SIG_LEN;
    uint8_t attestation[CX_SHA256_SIZE + MAX_DER_SIG_LEN] = {0};
    uint8_t attestation_signature[MAX_DER_SIG_LEN];
    size_t attestation_signature_len = MAX_DER_SIG_LEN;
    uint8_t compressed_public_key[PUBLIC_KEY_LENGTH];
    uint8_t compressed_attestation_public_key[PUBLIC_KEY_LENGTH];

    PRINTF("challenge_hash: %.*H \n", CX_SHA256_SIZE, challenge_hash);

    // Derive private key, and use it to sign challenge hash
    if (bip32_derive_ecdsa_sign_hash_256(SEED_ID_CURVE_ID,
                                         SEED_ID_PATH,
                                         SEED_ID_PATH_LEN,
                                         CX_RND_RFC6979 | CX_LAST,
                                         CX_SHA256,
                                         challenge_hash,
                                         CX_SHA256_SIZE,
                                         signature,
                                         &signature_len,
                                         NULL)) {
        return SW_CHALLENGE_NOT_VERIFIED;
    }

    PRINTF("Signature: %.*H\n", signature_len, signature);

    // Concatenate challenge hash and SeedID signature and then hash it to get the attestation
    // challenge hash
    memcpy(attestation, challenge_hash, CX_SHA256_SIZE);
    memcpy(attestation + CX_SHA256_SIZE, signature, signature_len);

    PRINTF("Attestation: %.*H\n", sizeof(attestation), attestation);

    // Compute hash
    crypto_digest(attestation,
                  CX_SHA256_SIZE + signature_len,
                  attestation,
                  CX_SHA256_SIZE + signature_len);

    // Sign attestation challenge hash with device private key
    if (sign_attestion(attestation, attestation_signature, &attestation_signature_len)) {
        return SW_SIGNATURE_FAIL;
    }

    if (get_public_key(compressed_public_key)) {
        return SW_SIGNATURE_FAIL;
    }

    crypto_compress_public_key(ATTESTATION_PUBKEY, (uint8_t*) &compressed_attestation_public_key);

    return send_challenge(compressed_public_key,
                          signature,
                          signature_len,
                          compressed_attestation_public_key,
                          attestation_signature,
                          attestation_signature_len);
}
