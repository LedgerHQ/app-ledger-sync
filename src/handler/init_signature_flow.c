#include "init_signature_flow.h"
#include "../globals.h"
#include "sw.h"
#include "../crypto.h"

int handler_init_signature_flow(buffer_t *cdata) {
    crypto_private_key_t private_key;
    crypto_public_key_t session_key;
    uint8_t derivation_buffer[65] = {0};
    int ret;

    // Reset the context
    signer_reset();

    // Create session key

    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));

    if (crypto_generate_pair(&session_key, &private_key) != C_OK) {
        return io_send_sw(SW_BAD_STATE);
    }
    PRINTF("SESSION PRIVATE KEY: \n");
    PRINTF("%.*H\n", 32, private_key.d);
    if ((ret = crypto_ecdh(&private_key,
                           cdata->ptr + cdata->offset,
                           G_context.signer_info.session_encryption_key)) != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(ret);
    }
    ret = crypto_compress_public_key(session_key.W, G_context.signer_info.session_key);

    if (ret != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SW_BAD_STATE);
    }

    PRINTF("SESSION PUBLIC KEY: \n");
    PRINTF("%.*H\n", 32, private_key.d);
    PRINTF("SESSION ENCRYPTION KEY: \n");
    PRINTF("%.*H\n", 32, G_context.signer_info.session_encryption_key);

    // SeedID initialization

    ret =
        crypto_derive_private_key(&private_key, derivation_buffer, SEED_ID_PATH, SEED_ID_PATH_LEN);
    if (ret != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SW_BAD_STATE);
    }

    crypto_init_public_key(&private_key, &session_key, derivation_buffer + 1);
    ret = crypto_compress_public_key(derivation_buffer, G_context.stream.device_public_key);
    if (ret != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SW_BAD_STATE);
    }
    PRINTF("DEVICE PUBLIC KEY: %.*H\n", 33, G_context.stream.device_public_key);

    explicit_bzero(&private_key, sizeof(private_key));

    G_context.req_type = CONFIRM_BLOCK;

    return io_send_sw(SW_OK);
}