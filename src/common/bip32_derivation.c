/*****************************************************************************
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

#include "types.h"
#include "write.h"
#include "constants.h"

bool bip32_path_is_hardened(const uint32_t *bip32_path, size_t bip32_path_len) {
    for (size_t i = 0; i < bip32_path_len; i++) {
        if ((bip32_path[i] & 0x80000000u) == 0) {
            return false;
        }
    }
    return true;
}
#include "../crypto.h"

/**
 * Derives a private key and chain code from a parent private key. This function only performs
 * hardened derivation. [Note: this function is not part of crypto.h for unit testing purposes]
 * @param[in]  parent_private_key The parent private key. The private key must be 32 bytes long.
 * @param[in]  parent_chain_code The parent chain code. The chain code must be 32 bytes long.
 * @param[in]  index The index of the child private key to derive. (Note that this index will be
 * hardened)
 * @param[out] child_private_key The result of the private key derivation. The buffer must be 32
 * bytes long.
 * @param[out] child_chain_code The result of the chain code derivation. The buffer must be 32 bytes
 * long.
 * @return 0 on success, error number otherwise.
 */
static int bip32_derive_xpriv(uint8_t *parent_private_key,
                              uint8_t *parent_chain_code,
                              uint32_t index,
                              uint8_t *child_private_key,
                              uint8_t *child_chain_code) {
    // kpar: 32 bytes, parent private key
    // cpar: 32 bytes, parent chain code
    // point(p): returns the coordinate pair resulting from EC point multiplication (repeated
    // application of the EC group operation) of the secp256k1 base point with the integer p.
    // ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte
    // first. ser256(p): serializes the integer p as a 32-byte sequence, most significant byte
    // first. serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's
    // compressed form: (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of
    // the omitted y coordinate. parse256(p): interprets a 32-byte sequence as a 256-bit number,
    // most significant byte first.

    // # Algorithm:
    // - Check whether i ≥ 2^31 (whether the child is a hardened key).
    // - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) ||
    // ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
    // - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) ||
    // ser32(i)).
    // - Split I into two 32-byte sequences, IL and IR.
    // - The returned child key ki is parse256(IL) + kpar (mod n).
    // - The returned chain code ci is IR.
    // - In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed
    // with the next value for i. (Note: this has probability lower than 1 in 2^127)
    int ret = 0;
    uint8_t I[RAW_PUBLIC_KEY_LENGTH];
    union {
        uint8_t hard[MEMBER_KEY_LEN + 4];  // 0x00 || ser256(kpar) || ser32(i)
        struct {
            uint8_t compressed_public_key[MEMBER_KEY_LEN + 4];
            crypto_public_key_t public_key;
            uint8_t raw_public_key[RAW_PUBLIC_KEY_LENGTH + 1];
            crypto_private_key_t private_key;
        } soft;
    } data;

    LEDGER_ASSERT(parent_private_key != NULL, "Null parent_private_key\n");
    LEDGER_ASSERT(parent_chain_code != NULL, "Null parent_chain_code\n");
    LEDGER_ASSERT(child_private_key != NULL, "Null child_private_key\n");
    LEDGER_ASSERT(child_chain_code != NULL, "Null child_chain_code\n");

iteration:
    if (index >= 1u << 31u) {
        data.hard[0] = 0x00;
        memcpy(data.hard + 1, parent_private_key, PRIVATE_KEY_LEN);
        write_u32_be(data.hard, MEMBER_KEY_LEN, index);
        ret = crypto_hmac_sha512(parent_chain_code, 32, data.hard, sizeof(data.hard), I, sizeof(I));
        if (ret != 0) {
            return ret;
        }
    } else {
        crypto_init_private_key(parent_private_key, &data.soft.private_key);
        crypto_init_public_key(&data.soft.private_key,
                               &data.soft.public_key,
                               data.soft.raw_public_key + 1);
        data.soft.raw_public_key[0] = 0x04;
        ret = crypto_compress_public_key(data.soft.raw_public_key, data.soft.compressed_public_key);
        if (ret != 0) {
            return ret;
        }
        write_u32_be(data.soft.compressed_public_key, MEMBER_KEY_LEN, index);
        ret = crypto_hmac_sha512(parent_chain_code,
                                 32,
                                 data.soft.compressed_public_key,
                                 37,
                                 I,
                                 sizeof(I));
        if (ret != 0) {
            return ret;
        }
    }
    ret = crypto_ec_add_mod_n(parent_private_key, I, child_private_key);
    if (ret != 0) {
        return ret;
    }
    if (!crypto_ec_is_point_on_curve(child_private_key)) {
        index += 1;
        PRINTF("got iteration\n");
        goto iteration;
    }
    memcpy(child_chain_code, I + 32, 32);
    return ret;
}

int bip32_derive_xpriv_to_path(uint8_t *parent_private_key,
                               uint8_t *parent_chain_code,
                               uint32_t *path,
                               size_t path_len,
                               uint8_t *child_private_key,
                               uint8_t *child_chain_code) {
    int ret = 0;
    uint8_t kpar[32];
    uint8_t cpar[32];

    LEDGER_ASSERT(parent_private_key != NULL, "Null parent_private_key\n");
    LEDGER_ASSERT(parent_chain_code != NULL, "Null parent_chain_code\n");
    LEDGER_ASSERT(child_private_key != NULL, "Null child_private_key\n");
    LEDGER_ASSERT(child_chain_code != NULL, "Null child_chain_code\n");

    // Copy parent private key and chain code to temporary buffer
    memcpy(kpar, parent_private_key, PRIVATE_KEY_LEN);
    memcpy(cpar, parent_chain_code, 32);

    for (size_t i = 0; i < path_len; i++) {
        // If it's not our first iteration, set the parent to be equal to the child
        if (i > 0) {
            memcpy(kpar, child_private_key, 32);
            memcpy(cpar, child_chain_code, 32);
        }
        ret = bip32_derive_xpriv(kpar, cpar, path[i], child_private_key, child_chain_code);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}