#pragma once

#ifndef TEST
#include "ledger_assert.h"
#else
#include <assert.h>
#define LEDGER_ASSERT(x, y) assert(x)
#endif

/**
 * Check if the given BIP32 path is only composed of hardened paths.
 * @param[in]  bip32_path The BIP32 path to check.
 * @param[in]  bip32_path_len The length of the BIP32 path.
 * @return true if the BIP32 path is only composed of hardened paths, false otherwise.
 */
bool bip32_path_is_hardened(const uint32_t *bip32_path, size_t bip32_path_len);
/**
 * Derives a private key and chain code from a parent private key. This function only performs
 * hardened derivation. [Note: this function is not part of crypto.h for unit testing purposes]
 * @param[in]  parent_private_key The parent private key. The private key must be 32 bytes long.
 * @param[in]  parent_chain_code The parent chain code. The chain code must be 32 bytes long.
 * @param[in]  path The path of the child private key to derive. (Note that this path will be
 * hardened)
 * @param[in]  path_len The length of the path.
 * @param[out] child_private_key The result of the private key derivation. The buffer must be 32
 * bytes long.
 * @param[out] child_chain_code The result of the chain code derivation. The buffer must be 32 bytes
 * long.
 * @return 0 on success, error number otherwise.
 */
int bip32_derive_xpriv_to_path(uint8_t *parent_private_key,
                               uint8_t *parent_chain_code,
                               uint32_t *path,
                               size_t path_len,
                               uint8_t *child_private_key,
                               uint8_t *child_chain_code);