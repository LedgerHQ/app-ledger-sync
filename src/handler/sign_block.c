#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "../sw.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "buffer.h"
#include "../block/block_parser.h"
#include "../block/signer.h"
#include "../helper/send_response.h"
#include "../block/trusted_properties.h"
#include "sign_block.h"
#include "../debug.h"
#include "../block/signer.h"
#include "../trusted_io.h"

int handler_sign_block(buffer_t *cdata, uint8_t mode) {
    int error;

    if (G_context.req_type != CONFIRM_BLOCK) {
        return io_send_sw(SW_BAD_STATE);
    }
    if (mode == MODE_BLOCK_START) {
        if (!IS_SESSION_INITIALIAZED()) {
            signer_reset();
            return io_send_sw(SW_BAD_STATE);
        }
        // Initialize the signer
        error = signer_init(&G_context.signer_info);
        if (error != 0) {
            signer_reset();
            return io_send_sw(SW_BAD_STATE);
        }
        // Expects to read a block header (version, issuer, parent...)
        error = signer_parse_block_header(&G_context.signer_info, &G_context.stream, cdata);

        if (error != 0) {
            signer_reset();
            return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
        }
        // Returns the issuer public key as trusted property
        buffer_t buffer = {.ptr = PIC(G_context.stream.device_public_key),
                           .size = sizeof(G_context.stream.device_public_key),
                           .offset = 0};
        io_init_trusted_property();
        io_push_trusted_property(TP_ISSUER_PUBLIC_KEY, &buffer);
        return io_send_trusted_property(SW_OK);

    } else if (mode == MODE_COMMAND_PARSE) {
        if (!IS_SESSION_INITIALIAZED()) {
            signer_reset();
            return io_send_sw(SW_BAD_STATE);
        }
        error = signer_parse_command(&G_context.signer_info, &G_context.stream, cdata);
        if (error != 0) {
            return io_send_sw(SW_BAD_STATE);
        }
        return io_send_trusted_property(SW_OK);
    } else if (mode == MODE_BLOCK_FINALIZE) {
        if (!IS_SESSION_INITIALIAZED()) {
            signer_reset();
            return io_send_sw(SW_BAD_STATE);
        }
        error = signer_sign_block(&G_context.signer_info, &G_context.stream);
        if (error != 0) {
            return io_send_sw(SW_BAD_STATE);
        }
        error = helper_send_response_block_signature();
        // Reset the context
        signer_reset();
        return error;
    }

    return io_send_sw(SW_BAD_STATE);
}