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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <string.h>  // memmove

#include "send_response.h"
#include "../constants.h"
#include "../globals.h"
#include "../sw.h"
#include "buffer.h"
#define MEMBER_SIZE(type, member) (sizeof(((type *) 0)->member))

int helper_send_response_pubkey() {
    return io_send_response_buffer(
        &(const buffer_t){.ptr = G_context.pk_info.compressed_pk,
                          .size = sizeof(G_context.pk_info.compressed_pk),
                          .offset = 0},
        SW_OK);
}

int helper_send_response_block_signature() {
    uint8_t resp[1 + MAX_DER_SIG_LEN + 1 + MEMBER_KEY_LEN] = {0};
    size_t offset = 0;

    resp[offset++] = G_context.signer_info.signature_len;
    memmove(resp + offset, G_context.signer_info.signature, G_context.signer_info.signature_len);
    offset += G_context.signer_info.signature_len;
    resp[offset++] = (uint8_t) G_context.signer_info.v;
    memmove(resp + offset, G_context.signer_info.session_key, MEMBER_KEY_LEN);
    offset += MEMBER_KEY_LEN;

    return io_send_response_buffer(&(const buffer_t){.ptr = resp, .size = offset, .offset = 0},
                                   SW_OK);
}
