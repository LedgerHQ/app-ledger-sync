#include "parse_stream.h"
#include "../globals.h"
#include "../sw.h"
#include "../stream/stream.h"
#include "../block/block_parser.h"
#include "../block/trusted_properties.h"
#include "../trusted_io.h"

static int handler_parse_header(buffer_t *data) {
    if (stream_parse_block_header(&G_context.stream, data) < 0) {
        return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
    }
    return io_send_sw(SW_OK);
}

static int handler_parse_command(buffer_t *data, parse_stream_output_mode_t output_mode) {
    uint8_t trusted_param_buffer[TP_BUFFER_SIZE_NEW_MEMBER];
    bool output_data = output_mode == OUTPUT_MODE_NONE;
    buffer_t trusted_param;

    int len = 0;

    if ((len = stream_parse_command(&G_context.stream,
                                    data,
                                    output_data == OUTPUT_MODE_NONE ? NULL : trusted_param_buffer,
                                    output_data ? sizeof(trusted_param_buffer) : 0)) < 0) {
        PRINTF("PARSE COMMAND FAILED\n");
        return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
    }

    if (output_data && len > 0) {
        trusted_param.ptr = trusted_param_buffer;
        trusted_param.size = len;
        trusted_param.offset = 0;
        io_init_trusted_property();
        io_push_trusted_property(TP_NEW_MEMBER, &trusted_param);
        return io_send_trusted_property(SW_OK);
    }

    if (G_context.stream.is_closed) {
        return io_send_sw(SW_STREAM_CLOSED);
    }

    return io_send_sw(SW_OK);
}

static int handler_parse_signature(buffer_t *data) {
    if (stream_parse_signature(&G_context.stream, data) < 0) {
        return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
    }
    return io_send_sw(SW_OK);
}

int handler_parse_stream(buffer_t *cdata,
                         parse_stream_mode_t parse_mode,
                         parse_stream_output_mode_t output_mode) {
    PRINTF("PARSE STREAM\n");

    // If secure flow was not initialized return an error
    if (!IS_SESSION_INITIALIAZED()) {
        return io_send_sw(SW_BAD_STATE);
    }

    // If parse_mode is set to empty stream reset the context and output success
    if (parse_mode == MODE_PARSE_EMPTY_STREAM) {
        stream_init(&G_context.stream);
        return io_send_sw(SW_OK);
    }

    // If parse_mode is set to block header and we expected something else, reset the context
    if (G_context.stream.parsing_state != STREAM_PARSING_STATE_BLOCK_HEADER &&
        parse_mode == MODE_PARSE_BLOCK_HEADER) {
        stream_init(&G_context.stream);
    }

    // If parse_mode is set to command and we expected something else, reset and output an error
    if (G_context.stream.parsing_state != STREAM_PARSING_STATE_COMMAND &&
        parse_mode == MODE_PARSE_COMMAND) {
        stream_init(&G_context.stream);
        return io_send_sw(SW_STREAM_PARSER_BAD_STATE);
    }

    // If parse_mode is set to signature and we expected something else, reset and output an error
    if (G_context.stream.parsing_state != STREAM_PARSING_STATE_SIGNATURE &&
        parse_mode == MODE_PARSE_SIGNATURE) {
        stream_init(&G_context.stream);
        return io_send_sw(SW_STREAM_PARSER_BAD_STATE);
    }

    // If parse_mode is set to block header and we expected a block header, parse the block header
    if (parse_mode == MODE_PARSE_BLOCK_HEADER) {
        PRINTF("PARSE STREAM HEADER\n");
        return handler_parse_header(cdata);
    }

    // If parse_mode is set to command and we expected a command, parse the command
    if (parse_mode == MODE_PARSE_COMMAND) {
        PRINTF("PARSE STREAM COMMAND\n");
        return handler_parse_command(cdata, output_mode);
    }

    // If parse_mode is set to signature and we expected a signature, parse the signature
    if (parse_mode == MODE_PARSE_SIGNATURE) {
        return handler_parse_signature(cdata);
    }

    return io_send_sw(SW_WRONG_P1P2);
}