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

#ifdef HAVE_NBGL

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../sw.h"
#include "action/validate.h"
#include "../menu.h"
#include "challenge_parser.h"

static uint8_t host[HOST_LENGTH];
int seed_id_callback(bool approve);
int add_member_confirm(void);
int add_seed_callback(bool approve);

static void ui_seed_id_callback(bool approve) {
    seed_id_callback(approve);
    ui_menu_main();
}

static void ui_add_seed_callback(bool approve) {
    add_seed_callback(approve);
    ui_menu_main();
}

static void ui_add_member_callback(bool approve) {
    if (approve) {
        add_member_confirm();
    } else {
        io_send_sw(SW_DENY);
    }
}

int ui_display_add_seed_command(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "Create a new\nsync group ?",
                       NULL,
                       "Yes",
                       "No",
                       ui_add_seed_callback);
    return 0;
}

int ui_display_add_member_command(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "Activate\nWallet Sync ?",
                       NULL,
                       "Yes",
                       "No",
                       ui_add_member_callback);

    return 0;
}

int ui_display_add_member_confirmed(void) {
    nbgl_useCaseStatus("WALLET SYNC\nACTIVATED", true, ui_menu_main);
    return 0;
}

int ui_display_seed_id_command(uint8_t* in_host) {
    memcpy(host, in_host, sizeof(host));
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "SeedID request from:",
                       (const char*) host,
                       "Approve",
                       "Reject",
                       ui_seed_id_callback);
    return 0;
}
#endif
