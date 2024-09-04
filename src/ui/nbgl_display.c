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

// FLOW to display add member (Turn On sync):
static void ui_add_member_callback(bool approve) {
    if (approve) {
        add_member_confirm();
        nbgl_useCaseStatus("Sync requested", true, ui_menu_main);
    } else {
        io_send_sw(SW_DENY);
        nbgl_useCaseStatus("Sync cancelled", false, ui_menu_main);
    }
}

int ui_display_add_member_command(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(NULL,
                       "Turn on sync for this phone or computer?",
                       "Your crypto accounts on Ledger Live will be synced.",
                       "Turn on sync",
                       "Don't sync",
                       ui_add_member_callback);
    return 0;
}

// FLOW to display Seed_ID (Connect):
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
                centeredInfo.text1 = "Error while connecting";
                centeredInfo.text2 =
                    "Try again. If this error repeats, contact Ledger Support at "
                    "support.ledger.com";
                centeredInfo.icon = &C_Denied_Circle_64px;
                centeredInfo.style = LARGE_CASE_INFO;
                status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
                if (status < 0) return;

                // draw screen
                nbgl_layoutDraw(layoutCtx);
                nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH,
                                                   POST_REFRESH_FORCE_POWER_ON);
            } else if (!index) {
                nbgl_useCaseStatus("Connection requested", true, ui_menu_main);
            } else {
                nbgl_useCaseStatus("Connection cancelled", false, ui_menu_main);
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
    centeredInfo.text1 = "Connect with\nLedger Sync?";
    centeredInfo.text2 = "Make sure to use Ledger Live only on a trusted phone or computer.";
    centeredInfo.style = LARGE_CASE_INFO;
    status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
    if (status < 0) return -1;

    // Add top icon for Privacy Report
    status = nbgl_layoutAddTopRightButton(layoutCtx, &C_privacy, TOKEN_PRIVACY, TUNE_TAP_CASUAL);
    if (status < 0) return -1;

    // Add choice buttons
    buttonInfo.topText = "Connect";
    buttonInfo.bottomText = "Don't connect";
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
            centeredInfo.text1 = "Error while connecting";
            centeredInfo.text2 =
                "Try again. If this error repeats, contact Ledger Support at support.ledger.com.";
            centeredInfo.icon = &C_Denied_Circle_64px;
            centeredInfo.style = LARGE_CASE_INFO;
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

int ui_display_seed_id_command(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(NULL,
                       "Connect with\nLedger Sync?",
                       "Make sure to use Ledger Live only on a trusted phone or computer.",
                       "Connect",
                       "Don't connect",
                       log_in_cb);
    return 0;
}
#endif

// FLOW to display update member (Remove and add back needed instances):
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
        centeredInfo.text1 = "Confirm change";
        centeredInfo.text2 = "Next, you will be asked to turn on sync to confirm the change.";
        centeredInfo.icon = &C_info_circle;
        centeredInfo.style = LARGE_CASE_INFO;
        status = nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);
        if (status < 0) return;

        // draw screen
        nbgl_layoutDraw(layoutCtx);
        nbgl_refreshSpecialWithPostRefresh(FULL_COLOR_CLEAN_REFRESH, POST_REFRESH_FORCE_POWER_ON);
    } else {
        nbgl_useCaseStatus("Removal cancelled", false, ui_menu_main);
    }
}

int ui_display_update_instances(void) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND
    nbgl_useCaseChoice(NULL,
                       "Remove phone or computer from\nLedger Sync?",
                       NULL,
                       "Remove",
                       "Keep",
                       ui_update_callback);
    return 0;
}

#endif
