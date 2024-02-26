#include "challenge_sign.h"
#include "challenge_parser.h"
#include "io.h"
#include "sw.h"
#include "globals.h"
#include "crypto_helpers.h"

#define MAX_CHALLENGE_RESP_SIZE (sizeof(pubkey_credential_t) + MAX_DER_SIG_LEN + MAX_DER_SIG_LEN)

static int send_challenge(uint8_t* compressed_public_key,
                          uint8_t* signature,
                          size_t signature_len,
                          uint8_t* attestation_signature,
                          size_t attestation_signature_len) {
    // Return SeedID public key + SeedID signature + Attestion PublicKey

    // TODO CHANGE THIS
    static uint8_t resp[MAX_CHALLENGE_RESP_SIZE] = {0};
    LEDGER_ASSERT(compressed_public_key != NULL, "Null pointer");
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

    memcpy(resp + offset, compressed_public_key, PUBLIC_KEY_LENGTH);
    offset += PUBLIC_KEY_LENGTH;

    // SeedID signature
    resp[offset++] = signature_len;
    memcpy(resp + offset, signature, signature_len);
    offset += signature_len;

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

    if (crypto_compress_public_key(raw_pubkey, compressed_public_key)) {
        return SW_SIGNATURE_FAIL;
    }

    return 0;
}

int verify_challenge_signature(challenge_ctx_t* challenge_ctx, uint8_t* challenge_hash) {
    LEDGER_ASSERT(challenge_ctx != NULL, "Null pointer");

    PRINTF("Verifying challenge signature\n");

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

    return send_challenge(compressed_public_key,
                          signature,
                          signature_len,
                          attestation_signature,
                          attestation_signature_len);
}