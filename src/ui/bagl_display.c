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

#ifdef HAVE_BAGL

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "glyphs.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../sw.h"
#include "action/validate.h"
#include "../menu.h"
#include "trusted_io.h"

static action_validate_cb g_validate_callback;
int add_member_confirm(void);
int add_seed_callback(bool confirm);

static action_validate_cb g_validate_callback;

static int ui_display_add_member(bool approve) {
    if (approve) {
        add_member_confirm();
    } else {
        io_send_sw(SW_DENY);
    }
    return 0;
}

UX_STEP_CB(ux_display_member_confirmed_step, nn, ui_menu_main(), {"Wallet sync", "activated"});

// FLOW to display add member:
// #1 screen: eye icon + "Confirm Address"
UX_FLOW(ux_display_member_confirmed_flow, &ux_display_member_confirmed_step);

// Step with icon and text
UX_STEP_NOCB(ux_display_confirm_member_step, pnn, {NULL, "Activate Wallet sync", NULL});

// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

// FLOW to display add member:
// #1 screen: eye icon + "Confirm Address"
// #2 screen: display address
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_add_member_flow,
        &ux_display_confirm_member_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_add_member_command(void) {
    g_validate_callback = &ui_display_add_member;
    ux_flow_init(0, ux_display_add_member_flow, NULL);
    return 0;
}

int ui_display_add_member_confirmed(void) {
    ux_flow_init(0, ux_display_member_confirmed_flow, NULL);
    return 0;
}

int ui_display_add_seed(bool approve) {
    add_seed_callback(approve);
    ui_menu_main();
    return 0;
}

UX_STEP_NOCB(ux_display_confirm_seed_step, nn, {"Create a new", "sync group"});

// FLOW to display add seed:
// #1 screen: eye icon + "Confirm Address"
// #2 screen: display address
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_add_seed_flow,
        &ux_display_confirm_seed_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_add_seed_command(void) {
    g_validate_callback = &ui_display_add_seed;
    ux_flow_init(0, ux_display_add_seed_flow, NULL);
    return 0;
}

#endif
