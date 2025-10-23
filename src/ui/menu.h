#pragma once

#ifdef SCREEN_SIZE_NANO
#define ICON_APP     C_home_app_14px
#define ICON_DENIED  C_icon_crossmark
#define ICON_INFO    C_Information_circle_14px
#define ICON_CONNECT C_Login_14px
#define ICON_TRASH   C_Trash_14px
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP     C_app_64px
#define ICON_DENIED  C_Denied_Circle_64px
#define ICON_INFO    C_Info_Circle_64px
#define ICON_CONNECT C_Login_64px
#define ICON_TRASH   C_Trash_64px
#elif defined(TARGET_APEX)
#define ICON_APP     C_app_48px
#define ICON_DENIED  C_Denied_Circle_48px
#define ICON_INFO    C_Info_Circle_48px
#define ICON_CONNECT C_Login_48px
#define ICON_TRASH   C_Trash_48px
#endif

/**
 * Show main menu (ready screen, version, about, quit).
 */
void ui_menu_main(void);

/**
 * Show about submenu (copyright, date).
 */
void ui_menu_about(void);
