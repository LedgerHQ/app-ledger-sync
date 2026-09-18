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
    tlv_t tlv = {0};

    int member_len = 0;
    int decrypted_len = 0;
    uint8_t *iv = NULL;
    uint8_t *member = NULL;
    uint8_t rawTrustedMember[TP_BUFFER_SIZE_NEW_MEMBER];
    uint8_t member_iv[IV_LEN];

    if (!IS_SESSION_INITIALIAZED()) {
        return io_send_sw(SW_BAD_STATE);
    }

    while (tlv_read_next(cdata, &tlv)) {
        switch (tlv.type) {
            case TP_IV:
                // AES-GCM always reads IV_LEN bytes from this pointer
                if (tlv.length != IV_LEN) {
                    return io_send_sw(SW_WRONG_DATA);
                }
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
    // The member property is a serialized trusted member encrypted with the session key
    if (iv == NULL || member == NULL ||
        member_len != (int) (TP_BUFFER_SIZE_NEW_MEMBER + CX_AES_BLOCK_SIZE)) {
        return io_send_sw(SW_WRONG_DATA);
    }

    derive_trusted_member_iv(iv, member_iv);
    decrypted_len = crypto_decrypt(G_context.signer_info.session_encryption_key,
                                   sizeof(G_context.signer_info.session_encryption_key),
                                   member,
                                   member_len,
                                   member_iv,
                                   rawTrustedMember,
                                   sizeof(rawTrustedMember));
    if (decrypted_len < 0) {
        return io_send_sw(SW_WRONG_DATA);
    }

    if (deserialize_trusted_member(rawTrustedMember,
                                   decrypted_len,
                                   &G_context.stream.trusted_member) < 0) {
        return io_send_sw(SW_WRONG_DATA);
    }

    return io_send_sw(SW_OK);
}
