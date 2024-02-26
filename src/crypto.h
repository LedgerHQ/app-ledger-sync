
#pragma once

#include <stdint.h>  // uint*_t
#include <stddef.h>
#include <stdio.h>
#include "constants.h"

#ifndef TEST

#include "os.h"
#include "cx.h"
#include "ledger_assert.h"

typedef cx_sha256_t crypto_hash_t;
typedef cx_ecfp_private_key_t crypto_private_key_t;
typedef cx_ecfp_public_key_t crypto_public_key_t;

#else
#include <lib/crypto.h>
#include <assert.h>
#define LEDGER_ASSERT(x, y) assert(x)
#endif

#define C_IV_LEN 16
#define C_ERROR  -1
#define C_OK     CX_OK

static const uint8_t ATTESTATION_KEY[] = {
    0x97, 0xcf, 0x0c, 0x79, 0xd5, 0x77, 0xc3, 0x48, 0x9e, 0x01, 0x4d, 0x69, 0x80, 0xef, 0xac, 0x5e,
    0x31, 0x7a, 0x99, 0x59, 0x57, 0xbc, 0xd5, 0xbc, 0x97, 0x24, 0xdc, 0xe6, 0x70, 0x7c, 0x8f, 0xda};

static const uint8_t ATTESTATION_PUBKEY[] = {
    0x04, 0xf1, 0x57, 0x32, 0x03, 0x31, 0xea, 0x2a, 0x70, 0xbb, 0x30, 0x75, 0xe8, 0xa8, 0xe6, 0xf9, 
    0xd6, 0x96, 0x81, 0x61, 0x43, 0xe9, 0xb3, 0xd6, 0xeb, 0x5c, 0x1a, 0xab, 0x5e, 0x6c, 0x7d, 0x0b, 
    0x69, 0x3a, 0x9d, 0xbe, 0xf9, 0xd5, 0xd2, 0xc8, 0x73, 0x70, 0x99, 0x9f, 0xfd, 0x9f, 0xd3, 0x39, 
    0x32, 0x0e, 0xd9, 0x01, 0x2f, 0xc6, 0xa8, 0xbe, 0x78, 0xf0, 0x61, 0xb8, 0x57, 0x27, 0x1c, 0xdb, 0x2b};

/**
 * Generate a new key pair.
 * @param[out] public_key
 *   Pointer to public key.
 * @param[out] private_key
 *   Pointer to private key.
 * @return 0 on success, error number otherwise.
 */
int crypto_generate_pair(crypto_public_key_t *public_key, crypto_private_key_t *private_key);

/**
 * Derive private key given BIP32 path.
 * @param[out] private_key
 *   Pointer to private key.
 * @param[out] chain_code
 *   Pointer to 32 bytes array for chain code.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 * @param[in]  bip32_path_len
 *   Number of path in BIP32 path.
 * @return 0 on success, error number otherwise.
 */
int crypto_derive_private_key(crypto_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len);

/**
 * Performs HMAC-SHA512.
 * @param[in]  key The key used to compute the HMAC.
 * @param[in]  key_len The length of the key.
 * @param[in]  data The data to compute the HMAC of.
 * @param[out] hmac The output buffer to store the hmac
 * @param[out] hmac_length The length of the output buffer.
 * @return 0 on success, error number otherwise.
 */
int crypto_hmac_sha512(uint8_t *key,
                       uint32_t key_len,
                       uint8_t *data,
                       uint32_t data_len,
                       uint8_t *hmac,
                       uint8_t hmac_len);

/**
 * Initialize public key given private key.
 * @param[in]  private_key
 *   Pointer to private key.
 * @param[out] public_key
 *   Pointer to public key.
 * @param[out] raw_public_key
 *   Pointer to raw public key.
 * @throw INVALID_PARAMETER
 */
void crypto_init_public_key(crypto_private_key_t *private_key,
                            crypto_public_key_t *public_key,
                            uint8_t raw_public_key[static 64]);

/**
 * Initialize private key given raw private key.
 * @param[in]  raw_private_key The raw private key. MUST BE 32 BYTES LONG.
 * @param[out] private_key The private key structure to initialize.
 */
void crypto_init_private_key(uint8_t raw_private_key[static 32], crypto_private_key_t *private_key);

/**
 * Compress public key.
 * @param[in]  public_key The public key to compress. Must be 65 bytes long (with 0x04 prefix).
 * @param[out] compressed_public_key The compressed public key. Must be 33 bytes long.
 * @return 0 on success, error number otherwise.
 */
int crypto_compress_public_key(const uint8_t *public_key, uint8_t compressed_public_key[static 33]);

/**
 * Decompress public key.
 * @param[in]  compressed_public_key The compressed public key. Must be 33 bytes long.
 * @param[out] public_key The decompressed public key. Must be 65 bytes long.
 * @return 0 on success, error number otherwise.
 */
int crypto_decompress_public_key(const uint8_t *compressed_public_key,
                                 uint8_t public_key[static RAW_PUBLIC_KEY_LENGTH + 1]);

/**
 * Perform ECDH between a private key and a compressed public key.
 */
int crypto_ecdh(const crypto_private_key_t *private_key,
                const uint8_t *compressed_public_key,
                uint8_t *secret);

/**
 * Generate ephemeral key pair and perform ECDH
 * @param[in]  recipient_public_key Compressed public key of the recipient.
 * @param[out] ephemeral_public_key The ephemeral public key used to compute the shared secret. The
 * buffer must be at least 33 bytes long.
 * @param[out] secret The shared secret. The buffer must be at least 32 bytes long.
 */
int crypto_ephemeral_ecdh(const uint8_t *recipient_public_key,
                          uint8_t *ephemeral_public_key,
                          uint8_t *secret);

/**
 * Performs an ephemeral ECDH and decrypts the given data.
 * @param[in]  private_key The private key of the recipient.
 * @param[in]  sender_public_key The public key of the sender.
 * @param[in]  data The data to decrypt.
 * @param[in]  data_len The length of the data to decrypt.
 * @param[in]  initialization_vector The initialization vector used to encrypt the data.
 * @param[out] decrypted_data The decrypted data. The buffer must be at least data_len bytes long.
 * @param[in]  decrypted_data_len The length of the decrypted data buffer.
 * @return The length of the decrypted data on success, a negative number in case of error.
 */
int crypto_ecdhe_decrypt(const crypto_private_key_t *private_key,
                         const uint8_t *sender_public_key,
                         const uint8_t *data,
                         uint32_t data_len,
                         uint8_t *initialization_vector,
                         uint8_t *decrypted_data,
                         uint32_t decrypted_data_len);

/**
 * Encrypt data with the given secret and IV
 * @param[in]  secret The secret used to encrypt the data.
 * @param[in]  secret_len The length of the secret.
 * @param[in]  data The data to encrypt.
 * @param[in]  data_len The length of the data to encrypt.
 * @param[in]  initialization_vector The initialization vector used to encrypt the data.
 * @param[out] encrypted_data The encrypted data. The buffer must be at least data_len bytes long.
 * @param[in]  encrypted_data_len The length of the encrypted data buffer.
 * @return The length of the encrypted data on success, a negative number in case of error.
 */
int crypto_encrypt(const uint8_t *secret,
                   uint32_t secret_len,
                   const uint8_t *data,
                   uint32_t data_len,
                   uint8_t *initialization_vector,
                   uint8_t *encrypted_data,
                   uint32_t encrypted_data_len,
                   bool padding);

/**
 * Decrypt data with the given secret and IV
 * @param[in]  secret The secret used to decrypt the data.
 * @param[in]  secret_len The length of the secret.
 * @param[in]  data The data to decrypt.
 * @param[in]  data_len The length of the data to decrypt.
 * @param[in]  initialization_vector The initialization vector used to decrypt the data.
 * @param[out] decrypted_data The decrypted data. The buffer must be at least data_len bytes long.
 * @param[in]  decrypted_data_len The length of the decrypted data buffer.
 * @return The length of the decrypted data on success, a negative number in case of error.
 */
int crypto_decrypt(const uint8_t *secret,
                   uint32_t secret_len,
                   const uint8_t *data,
                   uint32_t data_len,
                   uint8_t *initialization_vector,
                   uint8_t *decrypted_data,
                   uint32_t decrypted_data_len,
                   bool padding);

/**
 * Sign block hash in global context.
 * @see G_context.bip32_path, G_context.block_hash,
 * G_context.block_signature.
 * @return 0 on success, error number otherwise.
 */
int crypto_sign_block(void);

/**
 * Verify signature of a message hash.
 * @param[in] public_key The public key used to verify the signature.
 * @param[in] message_hash The message hash to verify.
 * @param[in] signature The signature to verify.
 * @param[in] signature_len The length of the signature.
 * @return 1 on success, 0 if the signature doesn't match, error number otherwise.
 */
int crypto_verify_signature(const uint8_t *public_key,
                            const uint8_t *digest,
                            uint8_t *signature,
                            size_t signature_len);

/**
 * Initialize the hash structure.
 * @param[out] hash The hash structure to initialize.
 */
void crypto_digest_init(crypto_hash_t *hash);

/**
 * Update the hash with the given data.
 * @param[in] hash The hash structure to update.
 * @param[in] data The data to hash.
 * @param[in] len The length of the data.
 */
void crypto_digest_update(crypto_hash_t *hash, const uint8_t *data, uint32_t len);

/**
 * Finalize the hash and store the digest in the given buffer.
 * @param[in]  hash The hash structure to finalize.
 * @param[out] digest The buffer to store the digest in.
 * @param[in]  len The length of the digest buffer.
 */
void crypto_digest_finalize(crypto_hash_t *hash, uint8_t *digest, uint32_t len);

/**
 * Compute the digest of the given data (single shot flavour).
 * @param[in]  data The data to hash.
 * @param[in]  len The length of the data.
 * @param[out] digest The buffer to store the digest in.
 * @param[in]  digest_len The length of the digest buffer.
 */
void crypto_digest(const uint8_t *data, uint32_t len, uint8_t *digest, uint32_t digest_len);

/**
 * Computes (a + b) % curve_order.
 * @param[in]  a The first number to add. Must be 32 bytes long.
 * @param[in]  b The second number to add. Must be 32 bytes long.
 * @param[out] out The buffer to store the result in. Must be 32 bytes long.
 * @return 0 on success, error code otherwise.
 */
int crypto_ec_add_mod_n(const uint8_t *a, const uint8_t *b, uint8_t *out);

/**
 * Check if the given private key is valid.
 * @param[in] private_key The private key to check. Must be 32 bytes long.
 * @return true if the private key is valid, false otherwise.
 */
bool crypto_ec_is_point_on_curve(const uint8_t *private_key);

/**
 * Generate a random private/public key pair.
 * @param[out] private_key The buffer to store the private key in. Must be 32 bytes long.
 * @param[out] public_key The buffer to store the public key in. Must be 65 bytes long.
 */
int crypto_generate_random_keypair(crypto_private_key_t *private_key,
                                   crypto_public_key_t *public_key);