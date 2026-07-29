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

/* NBGL implementation of all user-facing UI flows for this app.
 *
 * Each public ui_display_*() function is called from signer.c when a command
 * requires user approval. The function sets up the screen(s) and returns
 * immediately (NBGL is async); the APDU response is sent later from a callback.
 *
 * Flows in this file:
 *   1. ADD_MEMBER  — AppID 16: "Turn on sync for {name}?"         (1 screen)
 *   2. GET_SEED_ID — "Connect to Ledger Sync?"                    (1 screen)
 *   3. CLOSE_STREAM — "Remove from Ledger Sync?"                  (1 screen)
 */

#ifdef HAVE_NBGL

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
#include "../block/types.h"
#include "menu.h"
#include "challenge_parser.h"
#include "get_seed_id.h"
#include "signer.h"
#include "trusted_io.h"

/* Tokens for the SCREEN_SIZE_WALLET action-callback variant of GET_SEED_ID.
 * Nano uses a bool callback; WALLET uses a token-indexed callback — different NBGL APIs. */
enum {
    TOKEN_PRIVACY = FIRST_USER_TOKEN,
    TOKEN_LOG_IN,
    TOKEN_UPDATE,
};

nbgl_layout_t layoutCtx;

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW 1 — ADD_MEMBER AppID 16: "Turn on sync for Ledger Wallet / this website?"
 * Called by signer_inject_add_member when app_id == APP_ID_LEDGER_SYNC.
 * Strings are hardcoded per permission level; the member name is not displayed.
 * ───────────────────────────────────────────────────────────────────────────── */

static void ui_add_member_callback(bool approve) {
    if (approve) {
        add_member_confirm();
        nbgl_useCaseStatus("Sync requested", true, ui_menu_main);
    } else {
        io_send_sw(SW_DENY);
        nbgl_useCaseStatus("Sync cancelled", false, ui_menu_main);
    }
}

/**
 * @brief Ask the user to enable Ledger Sync for a new member (AppID 16).
 *
 * @param permissions  OWNER shows "Ledger Wallet" wording (view and update);
 *                     OWNER & ~CAN_ADD_BLOCK shows "this website" wording (view only).
 * @return 0; APDU response sent asynchronously via ui_add_member_callback.
 */
int ui_display_add_member_command(uint32_t permissions) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND

    if (permissions == OWNER) {
        nbgl_useCaseChoice(NULL,
#ifdef SCREEN_SIZE_WALLET
                           "Turn on sync\nfor Ledger Wallet?",
                           "Ledger Wallet will be able to view and update your synced accounts.",
#else
                           "Turn on sync\nfor Ledger Wallet?\f"
                           "Ledger Wallet will be able to view and update your synced accounts.",
                           NULL,
#endif
                           "Turn On sync",
                           "Don't sync",
                           ui_add_member_callback);
    } else if (permissions == (OWNER & ~CAN_ADD_BLOCK)) {
        nbgl_useCaseChoice(NULL,
#ifdef SCREEN_SIZE_WALLET
                           "Turn on sync for this website?",
                           "The website or dApp connected to your Ledger will be able to view your "
                           "synced accounts.",
#else
                           "Turn on sync for this website?\f"
                           "The website or dApp connected to your Ledger will be able to view your "
                           "synced accounts.",
                           NULL,
#endif
                           "Turn On sync",
                           "Don't sync",
                           ui_add_member_callback);
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW 2 — GET_SEED_ID: "Connect to Ledger Sync?"
 * ───────────────────────────────────────────────────────────────────────────── */

/* Forward declaration needed because the SCREEN_SIZE_WALLET variant of log_in_cb
 * calls ui_display_seed_id_command to restart the flow on error. */
int ui_display_seed_id_command(void);

#ifdef SCREEN_SIZE_WALLET
static void log_in_error_cb(int token, uint8_t index) {
    UNUSED(token);
    UNUSED(index);
    ui_menu_main();
}
#else
static void log_in_error_cb(nbgl_layout_t *layout, nbgl_buttonEvent_t event) {
    UNUSED(layout);
    UNUSED(event);
    ui_menu_main();
}
#endif

static void log_in_cb(bool confirm) {
    int error = -1;
    static nbgl_layoutDescription_t layoutDescription = {0};
    static nbgl_contentCenteredInfo_t centeredInfo = {0};
    int status = -1;

    error = seed_id_callback(confirm);
    if (confirm) {
        if (error == -1) {
            // add layout
            layoutDescription.onActionCallback = log_in_error_cb;
#ifdef SCREEN_SIZE_WALLET
            layoutDescription.tapActionText = "Tap to dismiss";
            layoutDescription.tapActionToken = TOKEN_LOG_IN;
#endif
            layoutCtx = nbgl_layoutGet(&layoutDescription);
            // add description
#ifdef SCREEN_SIZE_WALLET
            centeredInfo.text1 = "Error while connecting";
            centeredInfo.text2 =
                "Try again. If this error repeats, contact Ledger Support at support.ledger.com.";
            centeredInfo.icon = &ICON_DENIED;
            centeredInfo.style = LARGE_CASE_INFO;
#else
            centeredInfo.text1 = "Connection error";
            centeredInfo.text2 = "If this error repeats, contact Ledger Support.";
#endif
            status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
            if (status < 0) return;

            // draw screen
            nbgl_layoutDraw(layoutCtx);
            nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH,
                                               POST_REFRESH_FORCE_POWER_ON);
        } else {
            nbgl_useCaseStatus("Connection requested", true, ui_menu_main);
        }
    } else {
        nbgl_useCaseStatus("Connection cancelled", false, ui_menu_main);
    }
}

/**
 * @brief Ask the user to authenticate with Ledger Sync (GET_SEED_ID flow).
 * @return 0; response sent asynchronously via log_in_cb → seed_id_callback.
 */
int ui_display_seed_id_command(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(&ICON_CONNECT,
                       "Connect to\nLedger Sync?",
                       NULL,
                       "Connect",
                       "Don't connect",
                       log_in_cb);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW 3 — CLOSE_STREAM: "Remove from Ledger Sync?"
 * Triggered by CLOSE_STREAM command; on approval shows an info screen before
 * the subsequent ADD_MEMBER that confirms the change.
 * ───────────────────────────────────────────────────────────────────────────── */

/* SCREEN_SIZE_WALLET: post-approval info screen uses tap-to-continue token callback. */
#ifdef SCREEN_SIZE_WALLET
static void update_cb(int token, uint8_t index) {
    UNUSED(index);
    if (token == TOKEN_UPDATE) {
        io_send_trusted_property(SW_OK);
    }
    ui_menu_main();
}
#else
static void update_cb(nbgl_layout_t *layout, nbgl_buttonEvent_t event) {
    UNUSED(layout);
    UNUSED(event);
    io_send_trusted_property(SW_OK);
    ui_menu_main();
}
#endif

static void ui_update_callback(bool approve) {
    static nbgl_layoutDescription_t layoutDescription = {0};
    static nbgl_contentCenteredInfo_t centeredInfo = {0};
    int status = -1;

    update_confirm(approve);
    if (approve) {
        // add layout
        layoutDescription.onActionCallback = update_cb;
#ifdef SCREEN_SIZE_WALLET
        layoutDescription.tapActionText = "Tap to continue";
        layoutDescription.tapActionToken = TOKEN_UPDATE;
#endif
        layoutCtx = nbgl_layoutGet(&layoutDescription);
        // add description
#ifdef SCREEN_SIZE_WALLET
        centeredInfo.text1 = "Confirm change";
        centeredInfo.text2 = "Next, you will be asked to turn on sync to confirm the change.";
        centeredInfo.icon = &ICON_INFO;
        centeredInfo.style = LARGE_CASE_INFO;
#else
        centeredInfo.text1 = "Next, you will be asked to turn on sync to confirm the change.";
#endif
        status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
        if (status < 0) return;

        // draw screen
        nbgl_layoutDraw(layoutCtx);
        nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH, POST_REFRESH_FORCE_POWER_ON);
    } else {
        nbgl_useCaseStatus("Removal cancelled", false, ui_menu_main);
    }
}

/**
 * @brief Ask the user to confirm removing their Ledger Sync instances (CLOSE_STREAM).
 * @return 0; response sent asynchronously via ui_update_callback → update_confirm.
 */
int ui_display_update_instances(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(&ICON_TRASH,
                       "Remove from\nLedger Sync?",
                       NULL,
                       "Remove",
                       "Keep",
                       ui_update_callback);
    return 0;
}

#endif
