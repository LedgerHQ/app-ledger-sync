#include <crypto.h>
#include "hmac_sha2.h"
#include <string.h>
#include "bn.h"

typedef struct bn bn_t;

static const uint8_t SECP256K1_N[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2,
                                      0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static void bn_init(uint8_t *number, bn_t *n) {
    // Number must have a Big Endian representation
    bn_t k;
    bn_t c;

    bignum_init(n);

    for (int i = 0; i < 32; i++) {
        bignum_lshift(n, &k, 8); // n << (1 byte)
        bignum_assign(n, &k); // n = k
        bignum_from_int(&k, number[i]); // k = number[i]
        bignum_assign(&c, n); // c = n
        bignum_add(&c, &k, n); // n = k + c
    }
}

static void bn_to_bytes(bn_t *number, uint8_t *out) {
    bn_t n;
    bn_t k;
    bn_t c;

    bignum_assign(&n, number);
    bignum_from_int(&c, 0xFF);
    for (int i = 0; i < 32; i++) {
        bignum_and(&c, &n, &k); // k = n & 0xFF
        out[32 - i - 1] = (uint8_t) (bignum_to_int(&k) & 0xFF); // out[last] = k
        bignum_rshift(&n, &k, 8); // k = n >> 8
        bignum_assign(&n, &k); // n = k
    } 
}

int crypto_hmac_sha512(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *hmac) {
    hmac_sha512(key, key_len, data, data_len, hmac, 64);
    return 0;
}

void crypto_init_public_key(crypto_private_key_t *private_key,
                            crypto_public_key_t *public_key,
                            uint8_t raw_public_key[static 64]) {
    int ret = 0;
    uint8_t pubkey[65];
    size_t length = 65;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    ret = secp256k1_ec_pubkey_create(ctx, public_key, private_key->raw);
    if (ret == 1) {
        ret = secp256k1_ec_pubkey_serialize(ctx, pubkey, &length, public_key, SECP256K1_EC_UNCOMPRESSED);
        if (ret == 1) {
            memcpy(raw_public_key, pubkey + 1, 64);
        }
    }
    secp256k1_context_destroy(ctx);
}

void crypto_init_private_key(uint8_t raw_private_key[static 32], crypto_private_key_t *private_key) {
    memcpy(private_key->raw, raw_private_key, 32);
}

int crypto_compress_public_key(const uint8_t *public_key, uint8_t compressed_public_key[static 33]) {
    crypto_public_key_t pubkey;
    size_t length = 33;
    int ret = 0;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, public_key, 65);
    (void) ret;
    secp256k1_ec_pubkey_serialize(ctx, compressed_public_key, &length, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    return 0;
}

int crypto_ec_add_mod_n(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    bn_t bn_a;
    bn_t bn_b;
    bn_t bn_ab;
    bn_t bn_out;
    bn_t bn_n;

    bn_init((uint8_t *) SECP256K1_N, &bn_n);
    bn_init((uint8_t *) a, &bn_a);
    bn_init((uint8_t *) b, &bn_b);
    bignum_add(&bn_a, &bn_b, &bn_ab);
    bignum_mod(&bn_ab, &bn_n, &bn_out);
    bn_to_bytes(&bn_out, out);
    return 0;
}

bool crypto_ec_is_point_on_curve(const uint8_t *private_key) {
    bn_t bn_n;
    bn_t bn_p;

    bn_init((uint8_t *) SECP256K1_N, &bn_n);
    bn_init((uint8_t *) private_key, &bn_p);
    return bignum_cmp(&bn_p, &bn_n) == SMALLER;
}