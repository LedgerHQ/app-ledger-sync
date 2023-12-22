/*****************************************************************************
 *   Ledger App Trustchain.
 *   (c) 2023 Ledger SAS.
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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "../globals.h"
#include "../types.h"
#include "io.h"
#include "../sw.h"
#include "buffer.h"
#include "../helper/send_response.h"
#include "../constants.h"
#include "challenge_parser.h"

static int buffer_get_next_item(uint8_t* buffer,
                                uint8_t* buffer_remaining_len,
                                uint8_t* tag_label,
                                uint8_t* length,
                                uint8_t** value) {
    if (*buffer_remaining_len < VALUE_OFFSET) {
        return SW_PARSER_INVALID_FORMAT;
    }
    *tag_label = *(buffer + TAG_LABEL_OFFSET);
    *length = *(buffer + LENGTH_OFFSET);
    *value = (buffer + VALUE_OFFSET);

    if (*buffer_remaining_len < VALUE_OFFSET + *length) {
        return SW_PARSER_INVALID_FORMAT;
    }
    *buffer_remaining_len = *buffer_remaining_len - *length - VALUE_OFFSET;

    return 0;
}

int challenge_parse_buffer(buffer_t* buffer, challenge_ctx_t* challenge_ctx) {
    uint8_t tag_label;
    uint8_t length = 0;
    uint8_t* value = NULL;

    uint8_t* buffer_pointer = (uint8_t*) buffer->ptr;
    uint8_t remaining_len = buffer->size;

    int error = 0;

    // STRUCTURE_TYPE
    PRINTF("Structure Type\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != STRUCTURE_TYPE || length != sizeof(challenge_ctx->payload_type) ||
        *value != TYPE_SEED_ID__AUTHENTIFICATION_CHALLENGE) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    challenge_ctx->payload_type = value[0];

    // VERSION
    PRINTF("Version\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != VERSION || length != sizeof(challenge_ctx->version) ||
        *value != SEED_ID_VERSION) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    challenge_ctx->version = value[0];

    // CHALLENGE
    PRINTF("Challenge\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != CHALLENGE || length != sizeof(challenge_ctx->challenge_data)) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    memcpy(challenge_ctx->challenge_data, value, length);

    // SIGNER_ALGO
    PRINTF("Signer Algo\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != SIGNER_ALGO || length != sizeof(challenge_ctx->rp_credential_sign_algorithm) ||
        *value != SEED_ID_SIGN_ALGORTITHM) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    challenge_ctx->rp_credential_sign_algorithm = value[0];

    // DER_SIGNATURE
    PRINTF("DER Signature\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != DER_SIGNATURE || length > sizeof(challenge_ctx->rp_signature)) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    memcpy(challenge_ctx->rp_signature, value, length);

    // VALID_UNTIL
    PRINTF("Valid Until\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != VALID_UNTIL || length != sizeof(challenge_ctx->challenge_expiry)) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    memcpy(challenge_ctx->challenge_expiry, value, length);

    // TRUSTED_NAME
    PRINTF("Trusted Name\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != TRUSTED_NAME || length > sizeof(challenge_ctx->host) - 1) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    memcpy(challenge_ctx->host, value, length);
    challenge_ctx->host[length] = '\0';

    // PUBLIC_KEY_CURVE
    PRINTF("Public Key Curve\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != PUBLIC_KEY_CURVE || length != sizeof(challenge_ctx->rp_credential_curve_id) ||
        *value != SEED_ID_CURVE_ID) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    challenge_ctx->rp_credential_curve_id = value[0];

    // PUBLIC_KEY
    PRINTF("Public Key\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    buffer_pointer += length + VALUE_OFFSET;
    if (error) {
        return error;
    }

    if (tag_label != PUBLIC_KEY || length > sizeof(challenge_ctx->rp_credential_public_key)) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    memcpy(challenge_ctx->rp_credential_public_key, value, length);

    // PROTOCOL_VERSION
    PRINTF("Protocol Version\n");
    error = buffer_get_next_item(buffer_pointer, &remaining_len, &tag_label, &length, &value);
    if (error) {
        return error;
    }

    if (tag_label != PROTOCOL_VERSION || length != sizeof(challenge_ctx->protocol_version) ||
        !(value[0] == SEED_ID_PROTOCOL_VERSION_M && value[1] == SEED_ID_PROTOCOL_VERSION_N &&
          value[2] == SEED_ID_PROTOCOL_VERSION_P_UPPER &&
          value[3] == SEED_ID_PROTOCOL_VERSION_P_LOWER)) {
        return SW_PARSER_INVALID_VALUE;
    }

    PRINTF("\tValue: %.*H\n", length, value);
    PRINTF("\tLength: %d\n", length);
    memcpy(challenge_ctx->protocol_version, value, length);

    // Now buffer should be empty
    if (remaining_len != 0) {
        return SW_PARSER_INVALID_FORMAT;
    }

    return 0;
}
