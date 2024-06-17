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

#ifdef HAVE_BAGL

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "ux_flow_engine.h"
#include "glyphs.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../sw.h"
#include "menu.h"
#include "trusted_io.h"
#include "challenge_parser.h"
#include "get_seed_id.h"
#include "signer.h"

#define ux_flow_display(f) ux_flow_init(0, f, NULL)

UX_FLOW_CALL(ux_display_member_end, ui_menu_main());

UX_STEP_TIMEOUT(ux_display_member_confirmed_step,
                bn_paging,
                3000,
                ux_display_member_end,
                {.title = "", .text = "Ledger Sync enabled"});
UX_FLOW(ux_display_member_confirmed_flow, &ux_display_member_confirmed_step);

UX_STEP_TIMEOUT(ux_display_member_rejected_step,
                bn_paging,
                3000,
                ux_display_member_end,
                {.title = "", .text = "Operation cancelled"});
UX_FLOW(ux_display_member_rejected_flow, &ux_display_member_rejected_step);

static int ui_display_add_member(bool approve) {
    if (approve) {
        add_member_confirm();
        ux_flow_display(ux_display_member_confirmed_flow);
    } else {
        ux_flow_display(ux_display_member_rejected_flow);
        io_send_sw(SW_DENY);
    }
    return 0;
}

// FLOW to display add member:
UX_STEP_NOCB(ux_display_add_member_sync_step, pnn, {&C_app_16px, "Ledger Sync", "request"});
UX_STEP_NOCB(ux_display_add_member_trust_step,
             nnnn,
             {"Ensure you trust the", "mobile or desktop", "where Ledger Live is", "installed."});
UX_STEP_CB(ux_display_add_member_approve_step,
           pbb,
           ui_display_add_member(true),
           {&C_icon_validate_14, "Enable", "Ledger Sync"});
UX_STEP_CB(ux_display_add_member_reject_step,
           pb,
           ui_display_add_member(false),
           {
               &C_icon_crossmark,
               "Don't enable",
           });
UX_FLOW(ux_display_add_member_flow,
        &ux_display_add_member_sync_step,
        &ux_display_add_member_trust_step,
        &ux_display_add_member_approve_step,
        &ux_display_add_member_reject_step);

int ui_display_add_member_command(void) {
    ux_flow_display(ux_display_add_member_flow);
    return 0;
}

// FLOW to display seed id callback screens:
UX_STEP_CB(ux_display_seed_id_cb_signed_step,
           bnnn_paging,
           ui_menu_main(),
           {.title = "", .text = "Login request signed"});
UX_FLOW(ux_display_seed_id_cb_signed_flow, &ux_display_seed_id_cb_signed_step);

UX_STEP_TIMEOUT(ux_display_seed_id_cb_cancel_step,
                bn_paging,
                3000,
                ux_display_member_end,
                {.title = "", .text = "Login cancelled"});
UX_FLOW(ux_display_seed_id_cb_cancel_flow, &ux_display_seed_id_cb_cancel_step);

UX_STEP_CB(ux_display_seed_id_cb_error_step,
           bnnn_paging,
           ui_menu_main(),
           {.title = "Login error", .text = "If this occurs again, Contact Ledger Support."});
UX_FLOW(ux_display_seed_id_cb_error_flow, &ux_display_seed_id_cb_error_step);

static int ui_display_seed_id(bool approve) {
    int error;
    error = seed_id_callback(approve);
    if (error == -1) {
        ux_flow_display(ux_display_seed_id_cb_error_flow);
    } else if (!approve) {
        ux_flow_display(ux_display_seed_id_cb_cancel_flow);
    } else {
        ux_flow_display(ux_display_seed_id_cb_signed_flow);
    }
    return 0;
}

// FLOW to display seed id:
UX_STEP_NOCB(ux_display_seed_id_log_in_step, pnn, {&C_user, "Login request", "for Ledger Sync"});
UX_STEP_NOCB(ux_display_seed_id_identify_step,
             nnn,
             {"Identify with your", "Ledger Nano to use", "Ledger Sync?"});
UX_STEP_CB(ux_display_seed_id_approve_step,
           pbb,
           ui_display_seed_id(true),
           {&C_icon_validate_14, "Log in to", "Ledger Sync"});
UX_STEP_CB(ux_display_seed_id_reject_step,
           pb,
           ui_display_seed_id(false),
           {
               &C_icon_crossmark,
               "Cancel login",
           });
UX_FLOW(ux_display_seed_id_flow,
        &ux_display_seed_id_log_in_step,
        &ux_display_seed_id_identify_step,
        &ux_display_seed_id_approve_step,
        &ux_display_seed_id_reject_step);

int ui_display_seed_id_command() {
    ux_flow_display(ux_display_seed_id_flow);
    return 0;
}

// FLOW to display update instances callback screens:
UX_STEP_CB(ux_display_update_confirmed_step,
           bnnn_paging,
           ui_menu_main(),
           {.title = "", .text = "Ledger Sync updated"});
UX_FLOW(ux_display_update_confirmed_flow, &ux_display_update_confirmed_step);

UX_STEP_TIMEOUT(ux_display_update_rejected_step,
                bn_paging,
                3000,
                ux_display_member_end,
                {.title = "", .text = "Operation cancelled"});
UX_FLOW(ux_display_update_rejected_flow, &ux_display_update_rejected_step);

static int ui_display_update(bool approve) {
    update_confirm(approve);
    if (approve) {
        ux_flow_display(ux_display_update_confirmed_flow);
    } else {
        ux_flow_display(ux_display_update_rejected_flow);
    }
    return 0;
}

// FLOW to display update instances:
UX_STEP_NOCB(ux_display_update_sync_step, pnn, {&C_app_16px, "Ledger Sync", "update request"});
UX_STEP_NOCB(ux_display_update_trust_step,
             nnnn,
             {"This will remove", "existing instances to", "re-add those you'll", "keep"});
UX_STEP_CB(ux_display_update_approve_step,
           pb,
           ui_display_update(true),
           {&C_icon_validate_14, "Confirm"});
UX_STEP_CB(ux_display_update_reject_step,
           pb,
           ui_display_update(false),
           {
               &C_icon_crossmark,
               "Cancel",
           });
UX_FLOW(ux_display_update_flow,
        &ux_display_update_sync_step,
        &ux_display_update_trust_step,
        &ux_display_update_approve_step,
        &ux_display_update_reject_step);

int ui_display_update_instances(void) {
    ux_flow_display(ux_display_update_flow);
    return 0;
}

#endif
