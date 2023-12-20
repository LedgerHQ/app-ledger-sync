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

#include <stdio.h>    // snprintf
#include <string.h>   // memset, strlen
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "bip32.h"
#include "read.h"
#include "write.h"
#include "../crypto.h"

bool bip32_path_is_hardened(const uint32_t *bip32_path, size_t bip32_path_len) {
    for (size_t i = 0; i < bip32_path_len; i++) {
        if ((bip32_path[i] & 0x80000000u) == 0) {
            return false;
        }
    }
    return true;
}

int bip32_derive_xpriv(uint8_t *parent_private_key,
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
    uint8_t I[64];
    union {
        uint8_t hard[37];  // 0x00 || ser256(kpar) || ser32(i)
        struct {
            uint8_t compressed_public_key[33 + 4];
            crypto_public_key_t public_key;
            uint8_t raw_public_key[65];
            crypto_private_key_t private_key;
        } soft;
    } data;

iteration:
    if (index >= 1u << 31u) {
        data.hard[0] = 0x00;
        memcpy(data.hard + 1, parent_private_key, 32);
        write_u32_be(data.hard, 33, index);
        ret = crypto_hmac_sha512(parent_chain_code, 32, data.hard, sizeof(data.hard), I);
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
        write_u32_be(data.soft.compressed_public_key, 33, index);
        ret = crypto_hmac_sha512(parent_chain_code, 32, data.soft.compressed_public_key, 37, I);
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

    // Copy parent private key and chain code to temporary buffer
    memcpy(kpar, parent_private_key, 32);
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