/*****************************************************************************
 *   Ledger Sync App.
 *   (c) 2024 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "crypto.h"
#include "crypto_helpers.h"
#include "globals.h"

int crypto_generate_pair(crypto_public_key_t *public_key, crypto_private_key_t *private_key) {
    return cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, public_key, private_key, 0);
}

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    return bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                         bip32_path,
                                         bip32_path_len,
                                         private_key,
                                         chain_code);
}

void crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                            cx_ecfp_public_key_t *public_key,
                            uint8_t raw_public_key[static RAW_PUBLIC_KEY_LENGTH]) {
    // generate corresponding public key
    LEDGER_ASSERT(
        cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, public_key, private_key, 1) == CX_OK,
        "Generate pair error");
    if (raw_public_key != NULL) {
        memmove(raw_public_key, public_key->W + 1, RAW_PUBLIC_KEY_LENGTH);
    }
}

void crypto_init_private_key(uint8_t raw_private_key[static 32],
                             crypto_private_key_t *private_key) {
    LEDGER_ASSERT(
        cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, raw_private_key, 32, private_key) ==
            CX_OK,
        "Private key init failed");
}

void crypto_compress_public_key(const uint8_t *public_key,
                                uint8_t compressed_public_key[static MEMBER_KEY_LEN]) {
    for (int i = 0; i < 32; i++) {
        compressed_public_key[1 + i] = public_key[i + 1];
    }
    compressed_public_key[0] = (public_key[RAW_PUBLIC_KEY_LENGTH] & 1) ? 0x03 : 0x02;
}

static int ecpoint_decompress(uint8_t prefix, const uint8_t *raw_x, uint8_t *out_y) {
    // TODO REMOVE THIS FUNCTION AND USE BOLOS API
    uint8_t raw_p[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F};
    uint8_t raw_p_plus_one_div_4[] = {0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c};
    cx_bn_t p;
    cx_bn_t x;
    cx_bn_t y_square;
    cx_bn_t y_square_square_root;
    cx_bn_t constant;
    cx_bn_t swap;
    uint8_t raw_zero = 0;
    uint8_t raw_seven = 7;
    uint8_t exponent = 3;
    bool is_odd;
    cx_err_t error = CX_INTERNAL_ERROR;

    CX_CHECK(cx_bn_lock(32, 0));
    // y_square = 0
    CX_CHECK(cx_bn_alloc(&y_square, 32));
    // y_square_square_root = 0
    CX_CHECK(cx_bn_alloc(&y_square_square_root, 32));
    // x = raw_x
    CX_CHECK(cx_bn_alloc_init(&x, 32, raw_x, 32));
    // init p
    CX_CHECK(cx_bn_alloc_init(&p, 32, raw_p, sizeof(raw_p)));
    // init constant to 7
    CX_CHECK(cx_bn_alloc_init(&constant, 32, &raw_seven, sizeof(raw_seven)));
    // (pow_mod(x, 3, p) + 7) % p
    //  -> y_square = pow_mod(x, 3, p)
    CX_CHECK(cx_bn_mod_pow(y_square, x, &exponent, sizeof(exponent), p));
    // -> y_square = y_square + 7
    CX_CHECK(cx_bn_add(y_square, y_square, constant));
    // -> y_square = y_square % p
    CX_CHECK(cx_bn_reduce(y_square_square_root, y_square, p));
    // Swap y_square_square_root and y_square otherwise y_square is equal to 0
    swap = y_square_square_root;
    y_square_square_root = y_square;
    y_square = swap;
    // y = pow_mod(y_square, (p+1)/4, p)
    CX_CHECK(cx_bn_destroy(&constant));
    // Alloc constant to (p + 1) / 4
    CX_CHECK(cx_bn_alloc_init(&constant, 32, raw_p_plus_one_div_4, sizeof(raw_p_plus_one_div_4)));
    CX_CHECK(cx_bn_mod_pow_bn(y_square_square_root, y_square, constant, p));
    // Check parity
    CX_CHECK(cx_bn_is_odd(y_square_square_root, &is_odd));
    // prefix == "02" and y_square_square_root & 1 or
    // prefix == "03" and not y_square_square_root & 1
    if ((prefix == 0x02 && is_odd) || (prefix == 0x03 && !is_odd)) {
        // y_square_square_root = -y_square_square_root % p
        CX_CHECK(cx_bn_destroy(&constant));
        // Alloc constant to 0
        CX_CHECK(cx_bn_alloc_init(&constant, 32, &raw_zero, sizeof(raw_zero)));
        CX_CHECK(cx_bn_mod_sub(y_square, constant, y_square_square_root, p));
        // APDU_LOG_BN(y_square)
        CX_CHECK(cx_bn_export(y_square, out_y, 32));
    } else {
        CX_CHECK(cx_bn_export(y_square_square_root, out_y, 32));
    }
end:
    LEDGER_ASSERT(error == CX_OK, "Crypto Error");
    error |= cx_bn_destroy(&constant);
    error |= cx_bn_destroy(&y_square_square_root);
    error |= cx_bn_destroy(&y_square);
    if (cx_bn_is_locked()) {
        cx_bn_unlock();
    }
    return error;
}

int crypto_decompress_public_key(const uint8_t *compressed_public_key,
                                 uint8_t public_key[static RAW_PUBLIC_KEY_LENGTH + 1]) {
    cx_err_t error = CX_INTERNAL_ERROR;

    CX_CHECK(ecpoint_decompress(compressed_public_key[0],
                                compressed_public_key + 1,
                                public_key + 1 + 32));
    memcpy(public_key + 1, compressed_public_key + 1, 32);
    public_key[0] = 0x04;
end:
    return error;
}

int crypto_sign_block(void) {
    PRINTF("crypto_sign_block()\n");
    uint32_t info = 0;
    size_t sig_len = 0;
    cx_err_t error = CX_INTERNAL_ERROR;

    sig_len = sizeof(G_context.signer_info.signature);
    error = bip32_derive_with_seed_ecdsa_sign_hash_256(HDW_NORMAL,
                                                       CX_CURVE_256K1,
                                                       SEED_ID_PATH,
                                                       SEED_ID_PATH_LEN,
                                                       CX_RND_RFC6979 | CX_LAST,
                                                       CX_SHA256,
                                                       G_context.stream.last_block_hash,
                                                       sizeof(G_context.stream.last_block_hash),
                                                       G_context.signer_info.signature,
                                                       &sig_len,
                                                       &info,
                                                       NULL,
                                                       0);

    if (error == CX_OK) {
        G_context.signer_info.signature_len = sig_len;
        G_context.signer_info.v = (uint8_t) (info & CX_ECCINFO_PARITY_ODD);
    }
    return error;
}

/**
 * Perform ECDH between a private key and a compressed public key.
 */
int crypto_ecdh(const cx_ecfp_private_key_t *private_key,
                const uint8_t *compressed_public_key,
                uint8_t *secret) {
    cx_err_t error = CX_INTERNAL_ERROR;
    uint8_t raw_public_key[1 + RAW_PUBLIC_KEY_LENGTH] = {0};
    CX_CHECK(crypto_decompress_public_key(compressed_public_key, raw_public_key));
    error = cx_ecdh_no_throw(private_key, CX_ECDH_X, raw_public_key, 65, secret, 32);
end:
    explicit_bzero(&raw_public_key, sizeof(raw_public_key));
    return error;
}

int crypto_ephemeral_ecdh(const uint8_t *recipient_public_key,
                          uint8_t *out_ephemeral_public_key,
                          uint8_t *secret) {
    PRINTF("crypto_ephemeral_ecdh()\n");
    // Generate ephemeral keypair
    cx_err_t error = CX_INTERNAL_ERROR;
    cx_ecfp_private_key_t ephemeral_private_key;
    cx_ecfp_public_key_t ephemeral_public_key;

    CX_CHECK(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1,
                                            &ephemeral_public_key,
                                            &ephemeral_private_key,
                                            0));

    // Perform ECDH between ephemeral private key and recipient public key
    CX_CHECK(crypto_ecdh(&ephemeral_private_key, recipient_public_key, secret));

    // Compress ephemeral public key
    crypto_compress_public_key(ephemeral_public_key.W, out_ephemeral_public_key);

end:
    // Clean up
    explicit_bzero(&ephemeral_private_key, sizeof(ephemeral_private_key));
    return error;
}

int crypto_ecdh_decrypt(const uint8_t *sender_public_key,
                        const uint8_t *data,
                        uint32_t data_len,
                        uint8_t *initialization_vector,
                        uint8_t *decrypted_data,
                        uint32_t decrypted_data_len) {
    uint8_t secret[32];
    uint8_t chain_code[32] = {0};
    cx_ecfp_private_key_t private_key = {0};
    cx_err_t error = CX_INTERNAL_ERROR;

    // Initialize private key
    CX_CHECK(crypto_derive_private_key(&private_key, chain_code, SEED_ID_PATH, SEED_ID_PATH_LEN));

    // Compute secret key
    CX_CHECK(crypto_ecdh(&private_key, sender_public_key, secret));

    // Decrypt
    error = crypto_decrypt(secret,
                           sizeof(secret),
                           data,
                           data_len,
                           initialization_vector,
                           decrypted_data,
                           decrypted_data_len);
end:
    explicit_bzero(&secret, sizeof(secret));
    explicit_bzero(&private_key, sizeof(private_key));
    return error;
}

int crypto_encrypt(const uint8_t *secret,
                   uint32_t secret_len,
                   const uint8_t *data,
                   uint32_t data_len,
                   uint8_t *initialization_vector,
                   uint8_t *encrypted_data,
                   uint32_t encrypted_data_len) {
    cx_err_t error = CX_INTERNAL_ERROR;
    size_t out_len = data_len + CX_AES_BLOCK_SIZE;
    cx_aes_gcm_context_t ctx;
    PRINTF("crypto_encrypt()\n");

    if (encrypted_data_len < data_len + CX_AES_BLOCK_SIZE) {
        PRINTF("Buffer too small\n");
        error = CX_INTERNAL_ERROR;
        goto end;
    }

    cx_aes_gcm_init(&ctx);
    CX_CHECK(cx_aes_gcm_set_key(&ctx, secret, secret_len));
    error = cx_aes_gcm_encrypt_and_tag(&ctx,
                                       (uint8_t *) data,
                                       data_len,
                                       initialization_vector,
                                       CX_AES_BLOCK_SIZE,
                                       NULL,
                                       0,
                                       encrypted_data,
                                       encrypted_data + (out_len - CX_AES_BLOCK_SIZE),
                                       CX_AES_BLOCK_SIZE);
    if (error == CX_OK) {
        PRINTF("Data to encrypt: %.*H\n", data_len, data);
        PRINTF("Initialization vector: %.*H\n", CX_AES_BLOCK_SIZE, initialization_vector);
        PRINTF("Secret: %.*H\n", secret_len, secret);
        PRINTF("Successful Encrypted data: %.*H\n", out_len, encrypted_data);
        error = out_len;
    } else {
        PRINTF("Failed to encrypt data\n");
    }
end:
    explicit_bzero(&ctx, sizeof(ctx));
    return error;
}

int crypto_decrypt(const uint8_t *secret,
                   uint32_t secret_len,
                   const uint8_t *data,
                   uint32_t data_len,
                   uint8_t *initialization_vector,
                   uint8_t *decrypted_data,
                   uint32_t decrypted_data_len) {
    cx_err_t error = CX_INTERNAL_ERROR;
    cx_aes_gcm_context_t ctx;
    size_t out_len = decrypted_data_len;

    cx_aes_gcm_init(&ctx);
    CX_CHECK(cx_aes_gcm_set_key(&ctx, secret, secret_len));
    error = cx_aes_gcm_decrypt_and_auth(&ctx,
                                        (uint8_t *) data,
                                        data_len - CX_AES_BLOCK_SIZE,
                                        initialization_vector,
                                        CX_AES_BLOCK_SIZE,
                                        NULL,
                                        0,
                                        decrypted_data,
                                        data + (data_len - CX_AES_BLOCK_SIZE),
                                        CX_AES_BLOCK_SIZE);
    if (error == CX_OK) {
        PRINTF("Successful Decrypted data: %.*H\n", out_len, decrypted_data);
        error = out_len;
    } else {
        PRINTF("Failed to decrypt data\n");
    }
end:
    explicit_bzero(&ctx, sizeof(ctx));
    return error;
}

int crypto_verify_signature(const uint8_t *public_key,
                            const uint8_t *digest,
                            uint8_t *signature,
                            size_t signature_len) {
    cx_err_t error = CX_INTERNAL_ERROR;
    cx_ecfp_public_key_t pk;
    uint8_t raw_public_key[RAW_PUBLIC_KEY_LENGTH + 1] = {0};

    CX_CHECK(crypto_decompress_public_key(public_key, raw_public_key));
    PRINTF("PUBLIC KEY: %.*H\n", sizeof(raw_public_key), raw_public_key);
    PRINTF("HASH TO SIGN: %.*H\n", HASH_LEN, digest);
    PRINTF("SIGNATURE: %.*H\n", signature_len, signature);
    CX_CHECK(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1,
                                              raw_public_key,
                                              sizeof(raw_public_key),
                                              &pk));
    PRINTF("Verifying signature\n");
    error = cx_ecdsa_verify_no_throw(&pk, digest, CX_SHA256_SIZE, signature, signature_len) ? CX_OK
                                                                                            : -1;
end:
    return error;
}

void crypto_digest_init(crypto_hash_t *hash) {
    LEDGER_ASSERT(cx_sha256_init_no_throw((cx_sha256_t *) hash) == CX_OK, "Crypto digest error");
}

void crypto_digest_update(crypto_hash_t *hash, const uint8_t *data, uint32_t len) {
    LEDGER_ASSERT(cx_hash_no_throw((cx_hash_t *) hash, 0, data, len, NULL, 0) == CX_OK,
                  "Crypto digest error");
}

void crypto_digest_finalize(crypto_hash_t *hash, uint8_t *digest, uint32_t len) {
    LEDGER_ASSERT(cx_hash_no_throw((cx_hash_t *) hash, CX_LAST, NULL, 0, digest, len) == CX_OK,
                  "Crypto digest error");
}

void crypto_digest(const uint8_t *data, uint32_t len, uint8_t *digest, uint32_t digest_len) {
    LEDGER_ASSERT(cx_hash_sha256(data, len, digest, digest_len) == CX_SHA256_SIZE,
                  "Crypto digest error");
}

void crypto_hmac_sha512(uint8_t *key,
                        uint32_t key_len,
                        uint8_t *data,
                        uint32_t data_len,
                        uint8_t *hmac,
                        uint8_t hmac_len) {
    cx_hmac_sha512(key, key_len, data, data_len, hmac, hmac_len);
}

int crypto_ec_add_mod_n(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    cx_bn_t n;
    cx_bn_t a_bn;
    cx_bn_t b_bn;
    cx_bn_t out_bn;
    cx_err_t error = CX_INTERNAL_ERROR;

    CX_CHECK(cx_bn_lock(32, 0));
    CX_CHECK(cx_bn_alloc(&n, 32));
    CX_CHECK(cx_ecdomain_parameter_bn(CX_CURVE_256K1, CX_CURVE_PARAM_Order, n));
    CX_CHECK(cx_bn_alloc_init(&a_bn, 32, a, 32));
    CX_CHECK(cx_bn_alloc_init(&b_bn, 32, b, 32));
    CX_CHECK(cx_bn_alloc(&out_bn, 32));
    CX_CHECK(cx_bn_mod_add(out_bn, a_bn, b_bn, n));
    CX_CHECK(cx_bn_export(out_bn, out, 32));
end:
    LEDGER_ASSERT(error == CX_OK, "Crypto Error");
    error |= cx_bn_destroy(&a_bn);
    error |= cx_bn_destroy(&b_bn);
    error |= cx_bn_destroy(&out_bn);
    if (cx_bn_is_locked()) {
        cx_bn_unlock();
    }
    return error;
}

bool crypto_ec_is_point_on_curve(const uint8_t *private_key) {
    cx_bn_t n;
    cx_bn_t private_key_bn;
    int diff = 1;
    cx_err_t error = CX_INTERNAL_ERROR;

    CX_CHECK(cx_bn_lock(32, 0));
    CX_CHECK(cx_bn_alloc(&n, 32));
    CX_CHECK(cx_ecdomain_parameter_bn(CX_CURVE_256K1, CX_CURVE_PARAM_Order, n));
    CX_CHECK(cx_bn_alloc_init(&private_key_bn, 32, private_key, 32));
    CX_CHECK(cx_bn_cmp(private_key_bn, n, &diff));
end:
    if (error == CX_OK) {
        error |= cx_bn_destroy(&private_key_bn);
        error |= cx_bn_destroy(&n);
    }
    LEDGER_ASSERT(error == CX_OK, "Crypto Error");
    if (cx_bn_is_locked()) {
        cx_bn_unlock();
    }
    return diff;
}
