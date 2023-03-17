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

#include <stdint.h>
#include <stdbool.h>

#include "dispatcher.h"
#include "../constants.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../handler/get_version.h"
#include "../handler/get_app_name.h"
#include "../handler/get_public_key.h"
#include "../handler/sign_tx.h"
#include "../handler/sign_block.h"
#include "../handler/parse_stream.h"

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    buffer_t buf = {0};

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_version();
        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_app_name();
        case GET_PUBLIC_KEY:
            if (cmd->p1 > 0 || cmd->p2 > 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            // if (!cmd->data) {
            //    return io_send_sw(SW_WRONG_DATA_LENGTH);
            //}

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_get_public_key(&buf);
        case SIGN_TX:
            if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||  //
                cmd->p1 > P1_MAX ||                             //
                (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE)) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_sign_tx(&buf, cmd->p1, (bool) (cmd->p2 & P2_MORE));
        case SIGN_BLOCK:
            // If p1 is 0, Block header is expected
            // If p1 is 1, A single command is expected
            // if p1 is 2, the last command is expected (outputs the signature)
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_sign_block(&buf, cmd->p1, cmd->p2);
        case PARSE_STREAM:
            // This command is used to give context to the app before
            // making a signature.
            // P1 is used to describe the content of the chunk
            //  - 0x00: Block header
            //  - 0x01: Command
            //  - 0x02: Signature
            //  - 0x03: Init an empty stream
            // P2 is used to control the output
            //  - 0x00: No output
            //  - 0x01: Output trusted data

            if (cmd->p1 > MODE_PARSE_EMPTY_STREAM || cmd->p2 > OUTPUT_MODE_TRUSTED_DATA) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_parse_stream(&buf, cmd->p1, cmd->p2);
        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
