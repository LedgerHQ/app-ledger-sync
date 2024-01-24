/*****************************************************************************
 *   Ledger App Trustchain.
 *   (c) 2023 Ledger SAS.
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
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "../globals.h"
#include "../types.h"
#include "io.h"
#include "../sw.h"
#include "../crypto.h"
#include "buffer.h"
#include "../ui/display.h"
#include "../helper/send_response.h"
#include "../constants.h"
#include "challenge_parser.h"
#include "challenge_sign.h"

static uint8_t challenge_hash[CX_SHA256_SIZE];

int seed_id_callback(bool approve) {
    int error;

    if (approve) {
        error = sign_challenge(challenge_hash);
        if (error) {
            return io_send_sw(error);
        }
    } else {
        return io_send_sw(SW_DENY);
    }
    return 0;
}

int handler_get_seed_id(buffer_t* buffer) {
    int error;
    challenge_ctx_t challenge_ctx;
    LEDGER_ASSERT(buffer != NULL, "Null pointer");

    PRINTF("Parsing buffer\n");

    error = challenge_parse_buffer(buffer, &challenge_ctx);
    if (error) {
        PRINTF("Error parsing buffer: %d \n", error);
        return io_send_sw(error);
    }

    crypto_digest(buffer->ptr, buffer->size, challenge_hash, CX_SHA256_SIZE);

    error = verify_challenge_signature(&challenge_ctx, challenge_hash);
    if (error) {
        PRINTF("Error verifying challenge: %d \n", error);
        return io_send_sw(error);
    }

    ui_display_seed_id_command(challenge_ctx.host);

    return 0;
}
