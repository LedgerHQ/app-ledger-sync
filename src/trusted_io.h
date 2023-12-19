#pragma once

#include <stdint.h>
#include "buffer.h"

#define TRUSTED_IO_APDU_BUFFER_SIZE 258

/**
 * Initialize the IO state for pushing trusted properties.
 */
void io_init_trusted_property(void);

/**
 * Push a trusted property to the IO buffer.
 *
 * @param[in] property_type The type of the property to push.
 * @param[in] rdata The data of the property to push.
 */
int io_push_trusted_property(uint8_t property_type, buffer_t *rdata);

/**
 * Send pushed trusted properties to the host.
 *
 * @param[in] sw The status word to send with the properties. If the status word is not SW_OK, the
 * properties will not be sent.
 */
int io_send_trusted_property(uint16_t sw);
