#include "trusted_io.h"
#include "io.h"
#include "sw.h"
#include "trusted_properties.h"
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

static inline int io_push_cleartext_trusted_property(uint8_t property_type, buffer_t *rdata) {
    PRINTF("Push %d bytes\n", rdata->size - rdata->offset + 2);
    PRINTF("Remaining space: %d\n", sizeof(G_trusted_io_buffer) - G_trusted_output_len);
    if (G_trusted_output_len + rdata->size + 2 > sizeof(G_trusted_io_buffer)) {
        PRINTF("[ERROR] Trusted property buffer overflow\n");
        io_send_sw(SW_TP_BUFFER_OVERFLOW);
        return -1;
    }

    G_trusted_io_buffer[G_trusted_output_len] = property_type;
    G_trusted_output_len += 1;
    G_trusted_io_buffer[G_trusted_output_len] = rdata->size;
    G_trusted_output_len += 1;
    memcpy(G_trusted_io_buffer + G_trusted_output_len, rdata->ptr + rdata->offset, rdata->size);
    G_trusted_output_len += rdata->size;
    return 0;
}

static inline int io_push_encrypted_trusted_property(uint8_t property_type, buffer_t *rdata) {
    int length = 0;
    uint8_t *io_apdu_buffer = G_trusted_io_buffer + G_trusted_output_len;

    PRINTF("Push %d bytes\n", CRYPTO_BUFFER_SIZE(rdata->size - rdata->offset) + 2);
    PRINTF("Remaining space: %d\n", sizeof(G_trusted_io_buffer) - G_trusted_output_len);
    if (G_trusted_output_len + (rdata->size + 16 - (rdata->size % 16) + 2) >
        sizeof(G_trusted_io_buffer)) {
        PRINTF("[ERROR] Trusted property buffer overflow\n");
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
                            CRYPTO_BUFFER_SIZE(rdata->size - rdata->offset));

    if (length < 0) {
        PRINTF("[ERROR] Trusted property encryption failed\n");
        io_send_sw(SW_WRONG_DATA);
        return -1;
    }
    // Write length
    io_apdu_buffer[1] = length;
    G_trusted_output_len += length + 1;
    return 0;
}

int io_push_trusted_property(uint8_t property_type, buffer_t *rdata) {
    if ((property_type & TP_ENCRYPTED) == 0) {
        return io_push_cleartext_trusted_property(property_type, rdata);
    }
    return io_push_encrypted_trusted_property(property_type, rdata);
}

int io_send_trusted_property(uint16_t sw) {
    return io_send_response_pointer(G_trusted_io_buffer, G_trusted_output_len, sw);
}
