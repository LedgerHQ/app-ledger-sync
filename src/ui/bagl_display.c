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

#define POPUP_TIMEOUT 3000

#define ux_flow_display(f) ux_flow_init(0, f, NULL)

UX_FLOW_CALL(ux_back_to_idle, ui_menu_main());

UX_STEP_TIMEOUT(ux_display_member_confirmed_step,
                bn_paging,
                POPUP_TIMEOUT,
                ux_back_to_idle,
                {.title = "", .text = "Sync requested"});
UX_FLOW(ux_display_member_confirmed_flow, &ux_display_member_confirmed_step);

UX_STEP_TIMEOUT(ux_display_member_rejected_step,
                bn_paging,
                POPUP_TIMEOUT,
                ux_back_to_idle,
                {.title = "", .text = "Sync cancelled"});
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
UX_STEP_NOCB(ux_display_add_member_sync_step, nn, {"Turn on sync for this", "phone or computer?"});
UX_STEP_NOCB(ux_display_add_member_trust_step,
             nnn,
             {"Your crypto accounts", "on Ledger Live will", "be synced."});
UX_STEP_CB(ux_display_add_member_approve_step,
           pb,
           ui_display_add_member(true),
           {&C_icon_validate_14, "Turn on sync?"});
UX_STEP_CB(ux_display_add_member_reject_step,
           pb,
           ui_display_add_member(false),
           {
               &C_icon_crossmark,
               "Cancel",
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
           {.title = "", .text = "Connection requested"});
UX_FLOW(ux_display_seed_id_cb_signed_flow, &ux_display_seed_id_cb_signed_step);

UX_STEP_TIMEOUT(ux_display_seed_id_cb_cancel_step,
                bn_paging,
                POPUP_TIMEOUT,
                ux_back_to_idle,
                {.title = "", .text = "Connection cancelled"});
UX_FLOW(ux_display_seed_id_cb_cancel_flow, &ux_display_seed_id_cb_cancel_step);

UX_STEP_CB(ux_display_seed_id_cb_error_step,
           bnnn_paging,
           ui_menu_main(),
           {.title = "Connection error",
            .text = "If this occurs repeats, contact Ledger Support."});
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
UX_STEP_NOCB(ux_display_seed_id_log_in_step, nn, {"Connect with", "Ledger Sync?"});
UX_STEP_NOCB(ux_display_seed_id_identify_step,
             nnnn,
             {"Make sure to use", "Ledger Live only on a", "trusted phone or", "computer."});
UX_STEP_CB(ux_display_seed_id_approve_step,
           pbb,
           ui_display_seed_id(true),
           {&C_icon_validate_14, "Connect with", "Ledger Sync"});
UX_STEP_CB(ux_display_seed_id_reject_step,
           pb,
           ui_display_seed_id(false),
           {
               &C_icon_crossmark,
               "Don't connect",
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
UX_STEP_TIMEOUT(ux_display_update_confirmed_step,
                bnnn_paging,
                POPUP_TIMEOUT,
                ux_back_to_idle,
                {.title = "", .text = "Next, confirm change"});
UX_FLOW(ux_display_update_confirmed_flow, &ux_display_update_confirmed_step);

UX_STEP_TIMEOUT(ux_display_update_rejected_step,
                bn_paging,
                POPUP_TIMEOUT,
                ux_back_to_idle,
                {.title = "", .text = "Removal cancelled"});
UX_FLOW(ux_display_update_rejected_flow, &ux_display_update_rejected_step);

static int ui_display_update(bool approve) {
    update_confirm(approve);
    if (approve) {
        io_send_trusted_property(SW_OK);
        ux_flow_display(ux_display_update_confirmed_flow);
    } else {
        ux_flow_display(ux_display_update_rejected_flow);
    }
    return 0;
}

// FLOW to display update instances:
UX_STEP_NOCB(ux_display_update_sync_step,
             nnn,
             {"Remove phone or", "computer from", "Ledger Sync?"});
UX_STEP_NOCB(ux_display_update_trust_step,
             nnnn,
             {"After removing, you", "will be asked to turn", "on sync to confirm", "the change."});
UX_STEP_CB(ux_display_update_approve_step,
           pbb,
           ui_display_update(true),
           {&C_icon_validate_14, "Remove phone or", "computer"});
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
