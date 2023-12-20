#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>

#include <cmocka.h>
#include <string.h>
#include <stdio.h>
#include "base58.h"
#include "bip32.h"
#include "common/bip32_derivation.h"

// Test plan based on the BIP32 specification (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

typedef struct {
    uint8_t private[32];
    uint8_t chain_code[32];
} bip32_xpriv_t;

static int parse_b58xpriv(const char *b58_xpriv, bip32_xpriv_t *out) {
    // Xpriv serialization is specified in // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    uint8_t buffer[32 + 33 + 4 + 1 + 4 + 4 + 4]; 
    if (base58_decode(b58_xpriv, strlen(b58_xpriv), buffer, sizeof(buffer)) < 0) {
        printf("Failed to decode base58 string `%s`\n", b58_xpriv);
        return -1;
    } 

    memcpy(out->chain_code, buffer + 4 + 1 + 4 + 4, 32);
    memcpy(out->private, buffer + 4 + 1 + 4 + 4 + 32 + 1, 32); // skip 0x00 byte at the beginning of the private key
    return 0;
}

typedef struct {
    uint32_t path[MAX_BIP32_PATH];
    size_t path_len;
} bip32_path_t;

#define HARDENED 0x80000000

static int parse_derivation_path(const char *derivation_path, bip32_path_t *out) {
    out->path_len = 0;
    memset(out->path, 0, sizeof(out->path));

    for (int offset = 0; offset < strlen(derivation_path); offset++) {
        if (out->path_len >= MAX_BIP32_PATH) {
            printf("Derivation `%s` exceeds the max path len (%d)\n", derivation_path, MAX_BIP32_PATH);
            return -1;
        }
        if (derivation_path[offset] == '\'' || derivation_path[offset] == 'h') {
            out->path[out->path_len] |= HARDENED;
        } else if (derivation_path[offset] == '/') {
            out->path_len++;
        } else if (derivation_path[offset] >= '0' && derivation_path[offset] <= '9') {
            out->path[out->path_len] = out->path[out->path_len] * 10 + (derivation_path[offset] - '0');
        } else {
            printf("Invalid derivation path `%s`\n", derivation_path);
            return -1;
        }
    }
    out->path_len++;
    return 0;
}

static void test_bip32_derive_vector_1(void **state) {
    (void) state;
    const char *root_xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const char *derivations[] = { 
        "0h",
        "0h/1",
        "0h/1/2h",
        "0h/1/2h/2",
        "0h/1/2h/2/1000000000"
    };
    const char *expected_derivations[] = {
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    };
    bip32_xpriv_t root = {0};
    bip32_xpriv_t derived = {0};
    bip32_xpriv_t expected = {0};
    bip32_path_t  path = {0};

    parse_b58xpriv(root_xpriv, &root);

    for (int i = 0; i < sizeof(expected_derivations) / sizeof(expected_derivations[0]); i++) {
        parse_derivation_path(derivations[i], &path);
        bip32_derive_xpriv_to_path(root.private, root.chain_code, path.path, path.path_len, derived.private, derived.chain_code);
        parse_b58xpriv(expected_derivations[i], &expected);
        assert_memory_equal(&derived, &expected, sizeof(bip32_xpriv_t));
    }
} 

// Chain m
// ext pub: xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB
// ext prv: xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
// Chain m/0
// ext pub: xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH
// ext prv: xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt
// Chain m/0/2147483647H
// ext pub: xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a
// ext prv: xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9
// Chain m/0/2147483647H/1
// ext pub: xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon
// ext prv: xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef
// Chain m/0/2147483647H/1/2147483646H
// ext pub: xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL
// ext prv: xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc
// Chain m/0/2147483647H/1/2147483646H/2
// ext pub: xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt
// ext prv: xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j

static void test_bip32_derive_vector_2(void **state) {
    (void) state;
    const char *root_xpriv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
    const char *derivations[] = { 
        "0",
        "0/2147483647h",
        "0/2147483647h/1",
        "0/2147483647h/1/2147483646h",
        "0/2147483647h/1/2147483646h/2"
    };
    const char *expected_derivations[] = {
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    };
    bip32_xpriv_t root = {0};
    bip32_xpriv_t derived = {0};
    bip32_xpriv_t expected = {0};
    bip32_path_t  path = {0};

    parse_b58xpriv(root_xpriv, &root);

    for (int i = 0; i < sizeof(expected_derivations) / sizeof(expected_derivations[0]); i++) {
        parse_derivation_path(derivations[i], &path);
        bip32_derive_xpriv_to_path(root.private, root.chain_code, path.path, path.path_len, derived.private, derived.chain_code);
        parse_b58xpriv(expected_derivations[i], &expected);
        assert_memory_equal(&derived, &expected, sizeof(bip32_xpriv_t));
    }
} 

// Chain m
// ext pub: xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13
// ext prv: xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6
// Chain m/0H
// ext pub: xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y
// ext prv: xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L

static void test_bip32_derive_vector_3(void **state) {
    (void) state;
    const char *root_xpriv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
    const char *derivations[] = { 
        "0h"
    };
    const char *expected_derivations[] = {
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    };
    bip32_xpriv_t root = {0};
    bip32_xpriv_t derived = {0};
    bip32_xpriv_t expected = {0};
    bip32_path_t  path = {0};

    parse_b58xpriv(root_xpriv, &root);

    for (int i = 0; i < sizeof(expected_derivations) / sizeof(expected_derivations[0]); i++) {
        parse_derivation_path(derivations[i], &path);
        bip32_derive_xpriv_to_path(root.private, root.chain_code, path.path, path.path_len, derived.private, derived.chain_code);
        parse_b58xpriv(expected_derivations[i], &expected);
        assert_memory_equal(&derived, &expected, sizeof(bip32_xpriv_t));
    }
} 

// Chain m
// ext pub: xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa
// ext prv: xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv
// Chain m/0H
// ext pub: xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m
// ext prv: xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G
// Chain m/0H/1H
// ext pub: xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt
// ext prv: xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1

static void test_bip32_derive_vector_4(void **state) {
    (void) state;
    const char *root_xpriv = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv";
    const char *derivations[] = { 
        "0h",
        "0h/1h"
    };
    const char *expected_derivations[] = {
        "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    };
    bip32_xpriv_t root = {0};
    bip32_xpriv_t derived = {0};
    bip32_xpriv_t expected = {0};
    bip32_path_t  path = {0};

    parse_b58xpriv(root_xpriv, &root);

    for (int i = 0; i < sizeof(expected_derivations) / sizeof(expected_derivations[0]); i++) {
        parse_derivation_path(derivations[i], &path);
        bip32_derive_xpriv_to_path(root.private, root.chain_code, path.path, path.path_len, derived.private, derived.chain_code);
        parse_b58xpriv(expected_derivations[i], &expected);
        assert_memory_equal(&derived, &expected, sizeof(bip32_xpriv_t));
    }
} 

// Dont test vector 5 because it's focused on invalid xpriv, since we don't implement xpriv format serialization
// these tests are not relevant.

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_bip32_derive_vector_1),
                                       cmocka_unit_test(test_bip32_derive_vector_2),
                                       cmocka_unit_test(test_bip32_derive_vector_3),
                                       cmocka_unit_test(test_bip32_derive_vector_4)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
