#include "trusted_io.h"
#include "io.h"
#include "sw.h"
#include "block/trusted_properties.h"
#include "globals.h"

#define TP_IV_OFFSET 2
#define TP_IV_LEN    16

static uint32_t G_trusted_output_len = 0;
static uint8_t G_trusted_io_buffer[TRUSTED_IO_APDU_BUFFER_SIZE];

void io_init_trusted_property(void) {
    G_trusted_output_len = 0;
    // Serialize IV as TLV
    G_trusted_io_buffer[0] = TP_IV;
    G_trusted_io_buffer[1] = TP_IV_LEN;
    // Generate IV
    cx_trng_get_random_data(G_trusted_io_buffer + 2, TP_IV_LEN);

    G_trusted_output_len = TP_IV_LEN + 2;
}

int io_push_trusted_property(uint8_t property_type, buffer_t *rdata) {
    int length = 0;
    uint8_t *io_apdu_buffer = G_trusted_io_buffer + G_trusted_output_len;

    if (G_trusted_output_len + (rdata->size + 16 - (rdata->size % 16) + 2) >
        sizeof(G_trusted_io_buffer)) {
        io_send_sw(SW_TP_BUFFER_OVERFLOW);
        return -1;
    }

    io_apdu_buffer[0] = property_type;
    G_trusted_output_len += 1;

    // Encrypt the data using the session encryption key
    length = crypto_encrypt(G_context.signer_info.session_encryption_key,
                            sizeof(G_context.signer_info.session_encryption_key),
                            rdata->ptr + rdata->offset,
                            rdata->size - rdata->offset,
                            G_trusted_io_buffer + TP_IV_OFFSET,
                            io_apdu_buffer + 2,
                            sizeof(G_trusted_io_buffer) - G_trusted_output_len,
                            true);

    // Write length
    io_apdu_buffer[1] = length;
    G_trusted_output_len += length + 1;
    return 0;
}

int io_send_trusted_property(uint16_t sw) {
    return io_send_response_pointer(G_trusted_io_buffer, G_trusted_output_len, sw);
}