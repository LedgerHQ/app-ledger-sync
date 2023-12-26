#pragma once

#include <stdbool.h>  // bool

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef int (*action_validate_cb)(bool);

int ui_display_add_seed_command(void);

int ui_display_add_member_command(void);

int ui_display_add_member_confirmed(void);

int ui_display_seed_id_command(uint8_t* hostname);
