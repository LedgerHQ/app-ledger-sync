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
#include "menu.h"
#include "challenge_parser.h"
#include "get_seed_id.h"
#include "signer.h"
#include "trusted_io.h"

// #define WITH_PRIVACY_REPORT

enum {
    TOKEN_PRIVACY = FIRST_USER_TOKEN,
    TOKEN_LOG_IN,
    TOKEN_UPDATE,
};

nbgl_layout_t layoutCtx;

static void ui_add_member_callback(bool approve) {
    if (approve) {
        add_member_confirm();
        nbgl_useCaseStatus("Ledger Sync enabled", true, ui_menu_main);
    } else {
        io_send_sw(SW_DENY);
        nbgl_useCaseStatus("Operation cancelled", false, ui_menu_main);
    }
}

int ui_display_add_member_command(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(
        &C_app_64px,
        "Enable Ledger Sync?",
        "Make sure you trust the computer or smartphone on which Ledger Live is installed.",
        "Enable",
        "Cancel",
        ui_add_member_callback);
    return 0;
}

int ui_display_seed_id_command(void);

static void log_in_error_cb(int token, uint8_t index) {
    UNUSED(token);
    UNUSED(index);
    ui_menu_main();
}

#ifdef WITH_PRIVACY_REPORT
static void log_in_privacy_cb(void) {
    ui_display_seed_id_command();
}

#define MAX_PAIRS 3
static void log_in_cb(int token, uint8_t index) {
    int error = -1;
    static nbgl_layoutDescription_t layoutDescription = {0};
    static nbgl_contentCenteredInfo_t centeredInfo = {0};
    static nbgl_contentTagValue_t pairs[MAX_PAIRS];
    static nbgl_genericContents_t contents = {0};
    static nbgl_content_t contentsList = {0};
    uint8_t nbPairs = 0;
    int status = -1;

    switch (token) {
        case TOKEN_PRIVACY:
            // add tag/values
            pairs[nbPairs].item = "Data sharing";
            pairs[nbPairs].value = "Anonymous device identifier.";
            nbPairs++;
            pairs[nbPairs].item = "Why it's needed";
            pairs[nbPairs].value =
                "Uniquely identifying your Ledger device grants access to your Ledger Live "
                "features.";
            nbPairs++;
            pairs[nbPairs].item = "Data retrieval";
            pairs[nbPairs].value = "Connected wallets at the time of sharing.";
            nbPairs++;
            // Values to be reviewed
            contentsList.type = TAG_VALUE_LIST;
            contentsList.content.tagValueList.pairs = pairs;
            contentsList.content.tagValueList.nbPairs = nbPairs;
            contentsList.content.tagValueList.wrapping = true;
            // Generic page content
            contents.contentsList = &contentsList;
            contents.nbContents = 1;
            nbgl_useCaseGenericConfiguration("Privacy Report", 0, &contents, log_in_privacy_cb);
            break;

        case TOKEN_LOG_IN:
            error = seed_id_callback(index == 0);
            if (error == -1) {
                // add layout
                layoutDescription.onActionCallback = log_in_error_cb;
                layoutDescription.tapActionText = "Tap to dismiss";
                layoutDescription.tapActionToken = TOKEN_LOG_IN;
                layoutCtx = nbgl_layoutGet(&layoutDescription);
                // add description
                centeredInfo.text1 = "Ledger Sync login error";
                centeredInfo.text2 =
                    "If this error occurs, please contact Ledger Support for assistance.";
                centeredInfo.icon = &C_Denied_Circle_64px;
                centeredInfo.style = LARGE_CASE_INFO;
                status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
                if (status < 0) return;

                // draw screen
                nbgl_layoutDraw(layoutCtx);
                nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH,
                                                   POST_REFRESH_FORCE_POWER_ON);
            } else if (!index) {
                nbgl_useCaseStatus("Login request signed", true, ui_menu_main);
            } else {
                nbgl_useCaseStatus("Login cancelled", false, ui_menu_main);
            }
            break;
    }
}

int ui_display_seed_id_command(void) {
    nbgl_layoutDescription_t layoutDescription = {0};
    nbgl_contentCenteredInfo_t centeredInfo = {0};
    nbgl_layoutChoiceButtons_t buttonInfo = {0};
    int status = -1;

    // add layout
    layoutDescription.onActionCallback = log_in_cb;
    layoutCtx = nbgl_layoutGet(&layoutDescription);
    // add description
    centeredInfo.text1 = "Log in to Ledger Sync?";
    centeredInfo.text2 = "Identify with your Ledger device to manage Ledger Sync.";
    centeredInfo.icon = &C_log_in;
    centeredInfo.style = LARGE_CASE_INFO;
    status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
    if (status < 0) return -1;

    // Add top icon for Privacy Report
    status = nbgl_layoutAddTopRightButton(layoutCtx, &C_privacy, TOKEN_PRIVACY, TUNE_TAP_CASUAL);
    if (status < 0) return -1;

    // Add choice buttons
    buttonInfo.topText = "Log in";
    buttonInfo.bottomText = "Cancel";
    buttonInfo.token = TOKEN_LOG_IN;
    buttonInfo.style = ROUNDED_AND_FOOTER_STYLE;
    buttonInfo.tuneId = TUNE_TAP_CASUAL;
    status = nbgl_layoutAddChoiceButtons(layoutCtx, &buttonInfo);
    if (status < 0) return -1;

    // draw screen
    nbgl_layoutDraw(layoutCtx);
    nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH, POST_REFRESH_FORCE_POWER_ON);
    return 0;
}
#else
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
            layoutDescription.tapActionText = "Tap to dismiss";
            layoutDescription.tapActionToken = TOKEN_LOG_IN;
            layoutCtx = nbgl_layoutGet(&layoutDescription);
            // add description
            centeredInfo.text1 = "Ledger Sync login error";
            centeredInfo.text2 =
                "If this error occurs, please contact Ledger Support for assistance.";
            centeredInfo.icon = &C_Denied_Circle_64px;
            centeredInfo.style = LARGE_CASE_INFO;
            status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
            if (status < 0) return;

            // draw screen
            nbgl_layoutDraw(layoutCtx);
            nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH,
                                               POST_REFRESH_FORCE_POWER_ON);
        } else {
            nbgl_useCaseStatus("Login request signed", true, ui_menu_main);
        }
    } else {
        nbgl_useCaseStatus("Login cancelled", false, ui_menu_main);
    }
}

int ui_display_seed_id_command(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(&C_log_in,
                       "Log in to Ledger Sync?",
                       "Identify with your Ledger device to manage Ledger Sync.",
                       "Log in",
                       "Cancel",
                       log_in_cb);
    return 0;
}
#endif

static void update_cb(int token, uint8_t index) {
    UNUSED(index);
    if (token == TOKEN_UPDATE) {
        io_send_trusted_property(SW_OK);
    }
    ui_menu_main();
}

static void ui_update_callback(bool approve) {
    static nbgl_layoutDescription_t layoutDescription = {0};
    static nbgl_contentCenteredInfo_t centeredInfo = {0};
    int status = -1;

    update_confirm(approve);
    if (approve) {
        // add layout
        layoutDescription.onActionCallback = update_cb;
        layoutDescription.tapActionText = "Tap to continue";
        layoutDescription.tapActionToken = TOKEN_UPDATE;
        layoutCtx = nbgl_layoutGet(&layoutDescription);
        // add description
        centeredInfo.text1 = "Ledger Sync updated";
        centeredInfo.text2 =
            "You will be prompted to add back the remaining Ledger Live instances.";
        centeredInfo.icon = &C_Check_Circle_64px;
        centeredInfo.style = LARGE_CASE_INFO;
        status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
        if (status < 0) return;

        // draw screen
        nbgl_layoutDraw(layoutCtx);
        nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH, POST_REFRESH_FORCE_POWER_ON);
    } else {
        nbgl_useCaseStatus("Operation cancelled", false, ui_menu_main);
    }
}

int ui_display_update_instances(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Update Ledger Sync instances?",
                       "You'll need to remove existing Ledger Live instances in order to re-add "
                       "those you wish to keep active",
                       "Update",
                       "Cancel",
                       ui_update_callback);
    return 0;
}

#endif
