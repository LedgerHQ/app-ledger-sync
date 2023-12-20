#include "set_trusted_member.h"
#include "../common/tlv.h"
#include "../block/trusted_properties.h"
#include "../sw.h"
#include "../globals.h"

#define FLAG_IV_SET     = 1
#define FLAG_MEMBER_SET = 1 << 1;

int handler_set_trusted_member(buffer_t *cdata) {
    // Data are serialized as TLV
    // We only need the IV and member
    PRINTF("handler_set_trusted_member\n");
    tlv_t tlv;

    int member_len = 0;
    uint8_t *iv = NULL;
    uint8_t *member = NULL;
    uint8_t rawTrustedMember[TP_BUFFER_SIZE_NEW_MEMBER];

    if (!IS_SESSION_INITIALIAZED()) {
        return io_send_sw(SW_BAD_STATE);
    }

    while (tlv_read_next(cdata, &tlv)) {
        switch (tlv.type) {
            case TP_IV:
                iv = (uint8_t *) tlv.value;
                break;
            case TP_NEW_MEMBER:
                member = (uint8_t *) tlv.value;
                member_len = tlv.length;
                break;
            default:
                break;
        }
    }
    if (iv == NULL || member == NULL) {
        return io_send_sw(SW_WRONG_DATA);
    }
    if (crypto_decrypt(G_context.signer_info.session_key,
                       sizeof(G_context.signer_info.session_key),
                       member,
                       member_len,
                       iv,
                       rawTrustedMember,
                       sizeof(rawTrustedMember),
                       true) < 0) {
        return io_send_sw(SW_WRONG_DATA);
    }
    if (deserialize_trusted_member(rawTrustedMember,
                                   sizeof(rawTrustedMember),
                                   &G_context.stream.trusted_member) < 0) {
        return io_send_sw(SW_WRONG_DATA);
    }
    PRINTF("handler_set_trusted_member OK\n");
    return io_send_sw(SW_OK);
}