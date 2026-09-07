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
 *   1. ADD_MEMBER   — AppID 16 OWNER:                "Turn on sync for Ledger Wallet?" (1 screen)
 *      ADD_MEMBER   — AppID 16 OWNER&~CAN_ADD_BLOCK: "Turn on sync for {name}?"        (1 screen)
 *   2. GET_SEED_ID  — "Connect to Ledger Sync?"                                        (1 screen)
 *   3. CLOSE_STREAM — "Remove from Ledger Sync?"                                       (1 screen)
 *   4. ADD_MEMBER   — AppID 18 CAN_ENCRYPT|CAN_DERIVE: "Enable website access"         (2 screens)
 *   5. ADD_MEMBER   — AppID 18 CAN_ENCRYPT:            "Add agent"                     (1 screen)
 */

#ifdef HAVE_NBGL

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset

#include "os.h"
#include "cx.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"
#include "base58.h"

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

/* Buffer sizes for UI strings — derived from MAX_NAME_LEN (= 100).
 * UI_TEXT_LEN: Nano worst case is Register Agent screen 3, name appears twice:
 *   "Turn on sync for {name}?\f{name} will be able to view your synced accounts"
 *   = 2*MAX_NAME_LEN + 62 → rounded to 2*MAX_NAME_LEN + 80.
 * UI_BODY_LEN: WALLET body or subtext with name once:
 *   "{name} will be able to sync your accounts with Ledger Intent." = MAX_NAME_LEN + 56
 *   → rounded to MAX_NAME_LEN + 64.
 */
#define UI_TEXT_LEN (2 * MAX_NAME_LEN + 80)
#define UI_BODY_LEN (MAX_NAME_LEN + 64)

/* Agent fingerprint: base58 of the first FINGERPRINT_BYTES bytes of sha256(compressed pubkey),
 * displayed in groups of FINGERPRINT_GROUP_LEN characters and followed by the hint asking the
 * user to compare it with the one shown by the agent.
 * FINGERPRINT_CHARS_MAX: base58 expands by at most 138/100. */
#define FINGERPRINT_BYTES      10
#define FINGERPRINT_CHARS_MAX  (FINGERPRINT_BYTES * 138 / 100 + 1)
#define FINGERPRINT_GROUP_LEN  4
#define FINGERPRINT_GROUP_SEPS ((FINGERPRINT_CHARS_MAX - 1) / FINGERPRINT_GROUP_LEN)
#define FINGERPRINT_STR_LEN    (FINGERPRINT_CHARS_MAX + FINGERPRINT_GROUP_SEPS + 1)
#define FINGERPRINT_HINT       "Confirm this matches the ID appearing in your agent chat."
#ifdef SCREEN_SIZE_WALLET
/* WALLET holds the fingerprint and the hint in the single sub-message of the screen
  in order to keep the gray font. */
#define FINGERPRINT_HINT_SUFFIX "\n\n" FINGERPRINT_HINT
#define FINGERPRINT_TEXT_LEN    (FINGERPRINT_STR_LEN + sizeof(FINGERPRINT_HINT_SUFFIX) - 1)
#else
/* Nano gives the hint its own page, as the sub-message of the choice flow. */
#define FINGERPRINT_TEXT_LEN FINGERPRINT_STR_LEN
#endif

/* Dynamic string buffers — NBGL holds raw pointers to these across async callbacks,
 * so they must be static (stack frames are gone by the time callbacks fire). */
static char s_agent_fingerprint[FINGERPRINT_TEXT_LEN];
static char s_agent_sync_text[UI_TEXT_LEN];
static char s_agent_sync_subtext[UI_BODY_LEN];

/* ─────────────────────────────────────────────────────────────────────────────
 * Shared helpers — used across multiple flows.
 * ───────────────────────────────────────────────────────────────────────────── */

/* Sent as the nbgl_useCaseStatus callback for every rejection path.
 * SW_DENY must be deferred here (not before nbgl_useCaseStatus) so that
 * ragger's _check_async_error does not interrupt the screen-change wait
 * and fail to capture the cancel notification in snapshots. */
static void ui_deny_cb(void) {
    io_send_sw(SW_DENY);
    ui_menu_main();
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW ADD_MEMBER AppID 16: "Turn on sync for Ledger Wallet / {name}?"
 * Called by signer_inject_add_member when app_id == APP_ID_LEDGER_SYNC.
 * OWNER uses hardcoded "Ledger Wallet" wording; OWNER&~CAN_ADD_BLOCK uses member name.
 * ───────────────────────────────────────────────────────────────────────────── */

/** Shared approval callback for all ADD_MEMBER flows (AppID 16, AppID 18 OWNER and AGENT). */
static void ui_add_member_callback(bool approve) {
    if (approve) {
        add_member_confirm();
        nbgl_useCaseStatus("Sync requested", true, ui_menu_main);
    } else {
        nbgl_useCaseStatus("Sync cancelled", false, ui_deny_cb);
    }
}

/**
 * @brief Ask the user to enable Ledger Sync for a new member (AppID 16).
 *
 * @param permissions  OWNER shows "Ledger Wallet" wording (view and update);
 *                     OWNER & ~CAN_ADD_BLOCK shows the member name (view only).
 * @param name         Member name; used only for the OWNER & ~CAN_ADD_BLOCK case.
 * @return 0; APDU response sent asynchronously via ui_add_member_callback.
 */
void ui_display_add_member_command(uint32_t permissions, const char *name) {
#ifdef HAVE_PIEZO_SOUND
    // Play notification sound
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif  // HAVE_PIEZO_SOUND

    if (permissions == OWNER) {
        nbgl_useCaseChoice(NULL,
#ifdef SCREEN_SIZE_WALLET
                           "Turn on sync for Ledger Wallet?",
                           "Ledger Wallet will be able to view and update your synced accounts.",
#else
                           "Turn on sync for Ledger Wallet?\f"
                           "Ledger Wallet will be able to view and update your synced accounts.",
                           NULL,
#endif
                           "Turn On sync",
                           "Don't sync",
                           ui_add_member_callback);
    } else if (permissions == (OWNER & ~CAN_ADD_BLOCK)) {
        snprintf(s_agent_sync_subtext,
                 sizeof(s_agent_sync_subtext),
                 "%s will be able to view your synced accounts",
                 name);
#ifdef SCREEN_SIZE_WALLET
        snprintf(s_agent_sync_text, sizeof(s_agent_sync_text), "Turn on sync for %s?", name);
#else
        snprintf(s_agent_sync_text,
                 sizeof(s_agent_sync_text),
                 "Turn on sync for %s?\f%s",
                 name,
                 s_agent_sync_subtext);
#endif

        nbgl_useCaseChoice(NULL,
#ifdef SCREEN_SIZE_WALLET
                           s_agent_sync_text,
                           s_agent_sync_subtext,
#else
                           s_agent_sync_text,
                           NULL,
#endif
                           "Turn On sync",
                           "Don't sync",
                           ui_add_member_callback);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW GET_SEED_ID: "Connect to Ledger Sync?"
 * ───────────────────────────────────────────────────────────────────────────── */

/* Forward declaration needed because the SCREEN_SIZE_WALLET variant of log_in_cb
 * calls ui_display_seed_id_command to restart the flow on error. */

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
 */
void ui_display_seed_id_command(void) {
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
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW CLOSE_STREAM: "Remove from Ledger Sync?"
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
 */
void ui_display_update_instances(void) {
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
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW ADD_MEMBER AppID 18 + CAN_ENCRYPT|CAN_DERIVE: "Enable website access"
 *
 * add_member_confirm() is called on approval of the final screen in each flow.
 * Rejecting any screen shows a cancel notification; SW_DENY is deferred to ui_deny_cb.
 * ───────────────────────────────────────────────────────────────────────────── */

static void frontend_cb(bool approve) {
    if (approve) {
        add_member_confirm();
        nbgl_useCaseStatus("Access requested", true, ui_menu_main);
    } else {
        nbgl_useCaseStatus("Access cancelled", false, ui_deny_cb);
    }
}

/**
 * @brief Show "Enable website access for your agent?" screen (AppID 18, CAN_ENCRYPT|CAN_DERIVE).
 *
 * Pre-fills all dynamic string buffers before showing the first screen, because
 * NBGL holds raw pointers to these strings across the async callback chain.
 */
void ui_display_enable_agent_access(void) {
#ifdef HAVE_PIEZO_SOUND
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif
    nbgl_useCaseChoice(NULL,
                       "Allow agent to send proposals?",
                       NULL,
                       "Allow",
                       "Reject",
                       frontend_cb);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLOW ADD_MEMBER AppID 18 + CAN_ENCRYPT: "Add agent" (1 screen)
 *
 * add_member_confirm() is called on approval of the final screen in each flow.
 * Rejecting any screen shows a cancel notification; SW_DENY is deferred to ui_deny_cb.
 * ───────────────────────────────────────────────────────────────────────────── */

static void register_cb(bool approve) {
    if (approve) {
        add_member_confirm();
        nbgl_useCaseStatus("Registration requested", true, ui_menu_main);
    } else {
        nbgl_useCaseStatus("Registration cancelled", false, ui_deny_cb);
    }
}

/* Fill s_agent_fingerprint with the human-comparable identifier of the agent key, followed
 * by the comparison hint. Returns false if the fingerprint cannot be computed, so that no
 * screen is shown. */
static bool format_agent_fingerprint(const uint8_t *pubkey) {
    uint8_t hash[CX_SHA256_SIZE];
    char fingerprint[FINGERPRINT_CHARS_MAX];

    if (cx_hash_sha256(pubkey, MEMBER_KEY_LEN, hash, sizeof(hash)) != sizeof(hash)) {
        return false;
    }

    int len = base58_encode(hash, FINGERPRINT_BYTES, fingerprint, sizeof(fingerprint));
    if (len < 0) {
        return false;
    }

    // Space out the fingerprint in groups to ease the character by character comparison.
    size_t offset = 0;
    for (int i = 0; i < len; i++) {
        if ((i != 0) && ((i % FINGERPRINT_GROUP_LEN) == 0)) {
            s_agent_fingerprint[offset++] = ' ';
        }
        s_agent_fingerprint[offset++] = fingerprint[i];
    }

#ifdef SCREEN_SIZE_WALLET
    strlcpy(s_agent_fingerprint + offset,
            FINGERPRINT_HINT_SUFFIX,
            sizeof(s_agent_fingerprint) - offset);
#else
    s_agent_fingerprint[offset] = '\0';
#endif
    return true;
}

/**
 * @brief Show "Add agent" screen only (AppID 18, CAN_ENCRYPT).
 *
 * @param pubkey Agent compressed public key (MEMBER_KEY_LEN bytes); shown as base58 fingerprint.
 * @return SWO_NO_RESPONSE, the APDU response being sent asynchronously after the screen is
 *         confirmed, or an error status word if the fingerprint cannot be computed.
 */
int ui_display_register_agent_command(const uint8_t *pubkey) {
    if (!format_agent_fingerprint(pubkey)) {
        return SW_BAD_STATE;
    }

#ifdef HAVE_PIEZO_SOUND
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);
#endif

    nbgl_useCaseAdvancedChoiceWithDetails(&ICON_ROBOT,
                                          NULL,
#ifdef SCREEN_SIZE_WALLET
                                          "Add agent?",
                                          NULL,
                                          s_agent_fingerprint,
#else
                                          "Add agent",
                                          s_agent_fingerprint,
                                          FINGERPRINT_HINT,
#endif
                                          "Confirm and add",
                                          "Reject",
                                          NULL,
                                          register_cb);
    return SWO_NO_RESPONSE;
}

#endif
