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

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"

#include "../globals.h"
#include "menu.h"
extern void app_exit(void);

// 'About' menu
#define NB_INFO_FIELDS 2
static const char* const INFO_TYPES[] = {"Version", "Developer"};
static const char* const INFO_CONTENTS[] = {APPVERSION, "Ledger"};

void ui_menu_main(void) {
    static nbgl_contentInfoList_t infosList = {0};

    infosList.nbInfos = NB_INFO_FIELDS;
    infosList.infoTypes = (const char**) INFO_TYPES;
    infosList.infoContents = (const char**) INFO_CONTENTS;

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_app_64px,
                                "Use this app to sync your crypto accounts on Ledger Live across "
                                "different phones and computers.",
                                INIT_HOME_PAGE,
                                NULL,
                                &infosList,
                                NULL,
                                app_exit);
}

#endif
