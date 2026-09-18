#pragma once

#include <stdbool.h>  // bool
#include <stdint.h>   // uint8_t

void ui_display_add_member_command(uint32_t permissions, const char *name);

void ui_display_seed_id_command(void);

void ui_display_update_instances(void);

int ui_display_register_agent_command(const uint8_t *pubkey);

void ui_display_enable_agent_access(void);
