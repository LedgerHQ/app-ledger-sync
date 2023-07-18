/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
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
#include "globals.h"
#include "debug.h"

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    uint8_t raw_private_key[32] = {0};
    int error = 0;

    BEGIN_TRY {
        TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        }
    }
    END_TRY;

    return error;
}

int crypto_derive_xpriv(uint8_t *root_xpriv, const uint32_t *bip32_path, uint8_t bip32_path_len, uint8_t *xpriv, uint8_t *public_key) {
    // Implementation of https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
    int err = CX_OK;

    // BEGIN_TRY {
    //     TRY {
    //         os_perso_
    //     }
    // } CATCH_OTHER(e) {
    //     err = e;
    // } FINALLY {
        
    // }
    // END_TRY;

    return err;
}


void crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                            cx_ecfp_public_key_t *public_key,
                            uint8_t raw_public_key[static 64]) {
    // generate corresponding public key
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);
    memmove(raw_public_key, public_key->W + 1, 64);
}

int crypto_compress_public_key(const uint8_t *public_key, uint8_t compressed_public_key[static 33]) {
    for (int i = 0; i < 32; i++) {
       compressed_public_key[1 + i] = public_key[i + 1];
    }
    compressed_public_key[0] = (public_key[64] & 1) ? 0x03 : 0x02;
    return 0;
}

static int ecpoint_decompress(uint8_t prefix, const uint8_t *raw_x, uint8_t *out_y) {
    // TODO REMOVE THIS FUNCTION AND USE BOLOS API
    uint8_t raw_p[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F};
    uint8_t raw_p_plus_one_div_4[] = {0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c};
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
    int ret = 0;


    BEGIN_TRY {
        TRY {
            cx_bn_lock(32, 0);

            // y_square = 0
            cx_bn_alloc(&y_square, 32);

            // y_square_square_root = 0
            cx_bn_alloc(&y_square_square_root, 32);

            // x = raw_x
            cx_bn_alloc_init(&x, 32, raw_x, 32);

            // init p
            cx_bn_alloc_init(&p, 32, raw_p, sizeof(raw_p));

            // init constant to 7
            cx_bn_alloc_init(&constant, 32, &raw_seven, sizeof(raw_seven));
            
            // (pow_mod(x, 3, p) + 7) % p
            //  -> y_square = pow_mod(x, 3, p)
            cx_bn_mod_pow(y_square, x, &exponent, sizeof(exponent), p);
              
            // -> y_square = y_square + 7
            cx_bn_add(y_square, y_square, constant);
            
            // -> y_square = y_square % p
            cx_bn_reduce(y_square_square_root, y_square, p);
            
            // Swap y_square_square_root and y_square otherwise y_square is equal to 0
            swap = y_square_square_root;
            y_square_square_root = y_square;
            y_square = swap;
            
            // y = pow_mod(y_square, (p+1)/4, p)
            cx_bn_destroy(&constant);
            cx_bn_alloc_init(&constant, 32, raw_p_plus_one_div_4, sizeof(raw_p_plus_one_div_4)); // Alloc constant to (p + 1) / 4

            cx_bn_mod_pow_bn(y_square_square_root, y_square, constant, p);
            
            // Check parity
            cx_bn_is_odd(y_square_square_root, &is_odd);
            
            // prefix == "02" and y_square_square_root & 1) or (prefix == "03" and not y_square_square_root & 1
            if ((prefix == 0x02 && is_odd) || (prefix == 0x03 && !is_odd)) {
                // y_square_square_root = -y_square_square_root % p
                cx_bn_destroy(&constant);
                cx_bn_alloc_init(&constant, 32, &raw_zero, sizeof(raw_zero)); // Alloc constant to 0
                cx_bn_mod_sub(y_square, constant, y_square_square_root, p);
                //APDU_LOG_BN(y_square)
                cx_bn_export(y_square, out_y, 32);
            } else {
                cx_bn_export(y_square_square_root, out_y, 32);
            }
            
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            cx_bn_destroy(&constant);
            cx_bn_destroy(&y_square_square_root);
            cx_bn_destroy(&y_square);
            cx_bn_unlock();
        }
    } END_TRY;
    return ret;
}

int crypto_decompress_public_key(const uint8_t *compressed_public_key, uint8_t public_key[static 65]) {
    int error = 0;

    error = ecpoint_decompress(compressed_public_key[0], compressed_public_key + 1, public_key + 1 + 32);
    if (error != 0) {
        return error;
    } 
    memcpy(public_key + 1, compressed_public_key + 1, 32);
    public_key[0] = 0x04;
    return 0;
}

int crypto_sign_block(void) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info = 0;
    int sig_len = 0;

    // Derive private key
    int error = crypto_derive_private_key(&private_key,
                                          chain_code,
                                          SEED_ID_PATH,
                                          SEED_ID_PATH_LEN);
    
    cx_ecfp_public_key_t pk;
    uint8_t PK[65];
    uint8_t CPK[33];
    crypto_init_public_key(&private_key, &pk, PK + 1);
    crypto_compress_public_key(PK, CPK);
    if (error != 0) {
        return error;
    }
    DEBUG_LOG_BUF("PUBLIC KEY (SIGN): ", pk.W, pk.W_len);
    DEBUG_LOG_BUF("HASH TO SIGN (SIGN): ", G_context.stream.last_block_hash, HASH_LEN);
    // Sign hash of last block
    BEGIN_TRY {
        TRY {
            sig_len = cx_ecdsa_sign(&private_key,
                                    CX_RND_RFC6979 | CX_LAST,
                                    CX_SHA256,
                                    G_context.stream.last_block_hash,
                                    sizeof(G_context.stream.last_block_hash),
                                    G_context.signer_info.signature,
                                    sizeof(G_context.signer_info.signature),
                                    &info);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (error == 0) {
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
    int error = 0;
    uint8_t raw_public_key[65] = {0};
    if ((error = crypto_decompress_public_key(compressed_public_key, raw_public_key)) != 0) {
        return error;
    }
    BEGIN_TRY {
        TRY {
            cx_ecdh(private_key, CX_ECDH_X, raw_public_key, 65, secret, 32);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&raw_public_key, sizeof(raw_public_key));
        }
    }
    END_TRY;
    return error;
}

int crypto_ephemeral_ecdh(const uint8_t *recipient_public_key, uint8_t *out_ephemeral_public_key, uint8_t *secret) {
    // Generate ephemeral keypair
    int ret = 0;
    cx_ecfp_private_key_t ephemeral_private_key;
    cx_ecfp_public_key_t ephemeral_public_key;


    ret = cx_ecfp_generate_pair(CX_CURVE_256K1, &ephemeral_public_key, &ephemeral_private_key, 0);
    if (ret != 0) {
        return ret;
    }

    // Perform ECDH between ephemeral private key and recipient public key
    ret = crypto_ecdh(&ephemeral_private_key, recipient_public_key, secret);
    if (ret != 0) {
        explicit_bzero(&ephemeral_private_key, sizeof(ephemeral_private_key));
        return ret;
    }

    // Compress ephemeral public key
    ret = crypto_compress_public_key(ephemeral_public_key.W, out_ephemeral_public_key);

    // Clean up
    explicit_bzero(&ephemeral_private_key, sizeof(ephemeral_private_key));
    return ret;
}

int crypto_ecdhe_decrypt(const cx_ecfp_private_key_t *private_key, const uint8_t *sender_public_key, 
                         const uint8_t *data, uint32_t data_len, uint8_t *initialization_vector,
                         uint8_t *decrypted_data, uint32_t decrypted_data_len) {
    uint8_t secret[32];
    int ret = CX_OK;
    // Compute secret key
    ret = crypto_ecdh(private_key, sender_public_key, secret);
    if (ret != 0) {
        return ret;
    }

    // Decrypt
    ret = crypto_decrypt(secret, sizeof(secret), data, data_len, initialization_vector, decrypted_data, decrypted_data_len, false);
    return ret;
}

int crypto_encrypt(const uint8_t *secret, uint32_t secret_len, 
                   const uint8_t *data, uint32_t data_len, 
                   uint8_t *initialization_vector, uint8_t *encrypted_data, uint32_t encrypted_data_len, bool padding) {
    int ret = CX_OK;
    cx_aes_key_t key;

    ret = cx_aes_init_key(secret, secret_len, &key);
    if (ret < 0) {
        return ret;
    }
    ret = cx_aes_iv(
        &key, 
        CX_ENCRYPT | CX_CHAIN_CBC | CX_LAST | ( padding ? CX_PAD_ISO9797M2 : CX_PAD_NONE), 
        initialization_vector,
        C_IV_LEN, 
        data, 
        data_len, 
        encrypted_data, 
        encrypted_data_len
    );
    explicit_bzero(&key, sizeof(key));
    return ret;
}

int crypto_decrypt(const uint8_t *secret, uint32_t secret_len, 
                   const uint8_t *data, uint32_t data_len, 
                   uint8_t *initialization_vector, uint8_t *decrypted_data, uint32_t decrypted_data_len, bool padding) {
    int ret = CX_OK;
    cx_aes_key_t key;

    ret = cx_aes_init_key(secret, secret_len, &key);
    if (ret < 0) {
        return ret;
    }
    BEGIN_TRY {
        TRY {
            ret = cx_aes_iv(
                &key,
                CX_DECRYPT | CX_CHAIN_CBC | CX_LAST | (padding ? CX_PAD_ISO9797M2 : CX_PAD_NONE), 
                initialization_vector,
                C_IV_LEN, 
                data, 
                data_len, 
                decrypted_data, 
                decrypted_data_len
            );
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            explicit_bzero(&key, sizeof(key));
        }
    } END_TRY;
    return ret;
}

int crypto_verify_signature(const uint8_t *public_key,
                            crypto_hash_t *message_hash,
                            uint8_t *signature, size_t signature_len) {
    int ret = CX_OK;
    cx_ecfp_public_key_t pk;
    uint8_t raw_public_key[65] = {0};
    uint8_t digest[HASH_LEN] = {0};

    ret = crypto_decompress_public_key(public_key, raw_public_key);
    if (ret != CX_OK) {
        DEBUG_PRINT("Failed to decompress public key\n")
        return ret;
    }
    ret = crypto_digest_finalize(message_hash, digest, sizeof(digest));
    if (ret != CX_OK) {
        DEBUG_PRINT("Failed to finalize hash\n")
        return ret;
    }
    DEBUG_LOG_BUF("PUBLIC KEY: ", raw_public_key, sizeof(raw_public_key));
    DEBUG_LOG_BUF("HASH TO SIGN: ", digest, HASH_LEN);
    DEBUG_LOG_BUF("SIGNATURE: ", signature, signature_len);
    cx_ecfp_init_public_key(CX_CURVE_256K1, raw_public_key, sizeof(raw_public_key), &pk);
    DEBUG_PRINT("Verifying signature\n")
    return cx_ecdsa_verify_no_throw(&pk, digest, sizeof(digest), signature, signature_len);
}

int crypto_digest_init(crypto_hash_t *hash) {
    return cx_sha256_init((cx_sha256_t *) hash);
}

int crypto_digest_update(crypto_hash_t *hash, const uint8_t *data, uint32_t len) {
    int ret = CX_OK;
    BEGIN_TRY {
        TRY {
            cx_hash((cx_hash_t *) hash, 0, data, len, NULL, 0);
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            
        }
    } END_TRY;
    return ret;
}

int crypto_digest_finalize(crypto_hash_t *hash, uint8_t *digest, uint32_t len) {
    int ret = CX_OK;
    BEGIN_TRY {
        TRY {
            cx_hash((cx_hash_t *) hash, CX_LAST, NULL, 0, digest, len);
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            
        }
    } END_TRY;
    return ret;
}

int crypto_digest(const uint8_t *data, uint32_t len, uint8_t *digest, uint32_t digest_len) {
    return cx_hash_sha256(data, len, digest, digest_len);
}