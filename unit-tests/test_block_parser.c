#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>

#include "block/types.h"
#include "block/block_parser.h"
#include "buffer.h"
#include <stdio.h>

static void hex_to_buffer(const char* hex, buffer_t* buffer) {
    // Transform hex string to uint8_t array
    size_t len = strlen(hex);
    uint8_t* bytes = malloc(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &bytes[i / 2]);
    }
    buffer->offset = 0;
    buffer->ptr = bytes;
    buffer->size = len / 2;
}

static void atohex(const uint8_t* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

typedef struct {
    const char* topic;
    const uint16_t version;
    const char* group_key;
    const char* iv;
    const char* xpriv;
    const char* ephemeral_public_key;
} expected_seed_command_t;

static int assert_seed_command(buffer_t* buffer,
                               expected_seed_command_t* expectation,
                               block_command_t* out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_true(offset >= 0);

    assert_int_equal(command.type, COMMAND_SEED);
    char topic[65];
    atohex(command.command.seed.topic, 32, topic);
    assert_string_equal(expectation->topic, topic);
    char group_key[67];
    atohex(command.command.seed.group_public_key, 33, group_key);
    assert_string_equal(expectation->group_key, group_key);
    char ephemeral_public_key[67];
    atohex(command.command.seed.ephemeral_public_key, 33, ephemeral_public_key);
    assert_string_equal(expectation->ephemeral_public_key, ephemeral_public_key);
    char encrypted_xpriv[163];
    atohex(command.command.seed.encrypted_xpriv,
           sizeof(command.command.seed.encrypted_xpriv),
           encrypted_xpriv);
    assert_string_equal(expectation->xpriv, encrypted_xpriv);

    assert_int_equal(command.command.seed.protocol_version, expectation->version);

    if (out != NULL) {
        *out = command;
    }
    return offset;
}

typedef struct {
    const char* name;
    const char* public_key;
    const int permissions;
} expected_add_member_t;

static int assert_add_member_command(buffer_t* buffer,
                                     expected_add_member_t* expectation,
                                     block_command_t* out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_ADD_MEMBER);
    assert_string_equal(expectation->name, command.command.add_member.name);

    if (out != NULL) {
        *out = command;
    }
    return offset;
}

typedef struct {
    const char* initialization_vector;
    const char* encrypted_key;
    const char* recipient;
    const char* ephemeral_public_key;
} expected_publish_key_t;

static int assert_publish_key_command(buffer_t* buffer,
                                      expected_publish_key_t* expectation,
                                      block_command_t* out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_PUBLISH_KEY);
    char initialization_vector[33];
    atohex(command.command.publish_key.initialization_vector, 16, initialization_vector);
    assert_string_equal(expectation->initialization_vector, initialization_vector);
    char encrypted_key[2 * MAX_ENCRYPTED_KEY_LEN + 1];
    atohex(command.command.publish_key.encrypted_xpriv,
           command.command.publish_key.encrypted_xpriv_size,
           encrypted_key);
    assert_string_equal(expectation->encrypted_key, encrypted_key);
    char recipient[67];
    atohex(command.command.publish_key.recipient, 33, recipient);
    assert_string_equal(expectation->recipient, recipient);
    char ephemeral_public_key[67];
    atohex(command.command.publish_key.ephemeral_public_key, 33, ephemeral_public_key);
    assert_string_equal(expectation->ephemeral_public_key, ephemeral_public_key);

    if (out != NULL) {
        *out = command;
    }

    return offset;
}

static void test_block_header_parse(void** state) {
    (void) state;

    const char* stream =
        "01010102207f1781aef1d65ae5f6f48c4fee048090e008e0c29ebd30d4bc324f53b1f1"
        "919c0621021026de3be0412de9746be1a65b9e742d70504e10fb696ec98c958d1aae92"
        "d89c01010110d30520c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a"
        "2614741928510104000000000621022713c32352fceb1e3a4632a3cabc066cc00aa49b"
        "cfc0697d2bd6445dc6d71a7505107a307892d8835c0de6704c3a4f620ad4055110ecf2"
        "14c01f9daa8abb28bca2c01b968d000350158dd0153ec86ddab34a4be666ad2ee5ccd2"
        "12a4103bfd1001583b30714d21b429b94095cded2be403fb1324d81e35d3570b249f87"
        "f658eeb628f517c906210399ddd9c31422c2c82d8c04d5f0a05103f4db23a84ac913f4"
        "ce9cefcb5cff31000346304402207a789d70d2ce923fd28c427b4a4aa3ea03f548f7de"
        "35340ed6dc21a310edb45c02203ad3b54d750fa35073da52cf0f49512424a80dd676ee"
        "b19bc155e5b9623204b9";

    const char* expected_parent_hash =
        "7f1781aef1d65ae5f6f48c4fee048090e008e0c29ebd30d4bc324f53b1f1919c";

    const char* expected_issuer =
        "021026de3be0412de9746be1a65b9e742d70504e10fb696ec98c958d1aae92d89c";

    const int expect_length = 1;

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);

    block_header_t header;
    parse_block_header(&buffer, &header);

    char parent_hash[65];
    atohex(header.parent, 32, parent_hash);

    assert_int_equal(header.version, 1);
    assert_string_equal(parent_hash, expected_parent_hash);

    char issuer[67];
    atohex(header.issuer, 33, issuer);
    assert_string_equal(issuer, expected_issuer);

    assert_int_equal(header.length, expect_length);

    free((void*) buffer.ptr);
}

static void test_block_commands_parse(void** state) {
    (void) state;

    const char* stream =
        "0101010220271dfa2df29090187c03e15b566f2c3e563326ab506dea36424f8772f27b68ee06210329b172be36"
        "d4e784a770c27658a"
        "f4d46159de85ac07b1d34e6cf50755583ac7501010110c00520c96d450545ff2836204c29af291428a5bf74030"
        "4978f5dfb0b4a2614"
        "741928510102000006210378341775ca19ebaaa432da2c796910ae0fe40d22893c9b56456c6259b82992820510"
        "baddd1ccfaa164a33"
        "8bb264d5a3c3b290540f7364654d9b24b35c7152de05423ed3170e73782fb2ee029e75fdf02e03588fc7cf515b"
        "77d1a7f54327b950d"
        "4bc18a7e61a80df91257e67d2574b1c0aa7e86ad0621026bd2da8a1e4fb3b1085ebf7d873b0b0b4d3cc9fe1ae1"
        "d235ee7a75510c0c0"
        "c7c03473045022100d084f9c083dcbfdca37680fa679cbf7b8175e7e087146f1aa0f113272c485a50022068f08"
        "a702ccdbafa5e9a28"
        "7d8bab46d1925f10d11d68c86444f9c7fcbb4b43b0";
    const char* expected_topic = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851";

    const char* expected_signature =
        "3045022100d084f9c083dcbfdca37680fa679cbf7b8175e7e087146f1aa0f113272c485a50022068f08a702ccd"
        "bafa5e9a287d8bab46d"
        "1925f10d11d68c86444f9c7fcbb4b43b0";

    const char* expected_group_key =
        "0378341775ca19ebaaa432da2c796910ae0fe40d22893c9b56456c6259b8299282";

    const char* expected_ephemeral_public_key =
        "026bd2da8a1e4fb3b1085ebf7d873b0b0b4d3cc9fe1ae1d235ee7a75510c0c0c7c";

    const char* expected_encrypted_xpriv =
        "f7364654d9b24b35c7152de05423ed3170e73782fb2ee029e75fdf02e03588fc7cf515b77d1a7f54327b950d4b"
        "c18a7e61a80df9125"
        "7e67d2574b1c0aa7e86ad";

    const char* expected_initialization_vector = "baddd1ccfaa164a338bb264d5a3c3b29";

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);

    // Parse the block header
    block_header_t header;
    int offset = 0;
    offset = parse_block_header(&buffer, &header);
    buffer.offset = offset;  // Offset should be at the beginning of a command

    // Parse the command
    expected_seed_command_t seed_expectations = {
        .topic = expected_topic,
        .group_key = expected_group_key,
        .ephemeral_public_key = expected_ephemeral_public_key,
        .xpriv = expected_encrypted_xpriv,
        .iv = expected_initialization_vector,
        .version = 0,
    };
    assert_seed_command(&buffer, &seed_expectations, NULL);

    // Parse signature
    uint8_t signature[71];
    char sig_hex[143];
    memset((void*) signature, 0, sizeof(signature));

    parse_block_signature(&buffer, signature, sizeof(signature));
    atohex(signature, sizeof(signature), sig_hex);
    assert_string_equal(sig_hex, expected_signature);

    free((void*) buffer.ptr);
}

static void test_stream_parse(void** state) {
    (void) state;
    const char* stream =
        "0101010220ab9565de221ab57423a4b395e0db36bfe451a11394a62b8c347bf89ac78cd967062102550febeeac"
        "572b026ff35005d7eac"
        "961d022d6da0b3dfc09b5dd9497069b6efb01010110c00520c96d450545ff2836204c29af291428a5bf7403049"
        "78f5dfb0b4a26147419"
        "285101020000062103ab80381ce1f25cd242916bbbb99b3feb067fc49f9844ed167d28dda567ae04b605100d1c"
        "b422e09eefe91f67666"
        "30c0f95fe05401fb8fd54a5d4e2cbc846a9d40ac770099bd95032d6db17edd3e38d6b2d8d883e3a9f6d48430ae"
        "4aa4345ede589cb5651"
        "e179ad96b34481377749fa7c7f966ab5062103378aff702550fd188196e2a7731fc8f0958f31e47e85ae7c0d32"
        "b5137aee796e0346304"
        "4022040a9f6b3ca8b7aab0260bc53bc5d544597cb92ab8d4736c17f5fc990137a6e0202205e4fa3f21cdce016f"
        "dfbbc1ea3c6e78c1365"
        "94e4e8068ac5b2cccb4e7d0ac8c60101010220e0434c11beed87a586c57d5068bc59ec076b707a2ea280c9ea44"
        "cf1f618c70530621025"
        "50febeeac572b026ff35005d7eac961d022d6da0b3dfc09b5dd9497069b6efb010102112e0403426f620621031"
        "8a83c2c4eb8505f3869"
        "ae34a0fc0c99faad8d09441a4b6c25957878bae0986a010400000001129a05101659b1d3706ea17c56061e118e"
        "97049405400db0d57c7"
        "0f7b263ea4c90fd9f9f5da743a046c03e8c8ac3991283dbf3bb0629ac8038b1be1638dda9bd3a7aab2a1c8eac8"
        "2365bdebe73a353096a"
        "e3a09470e306210318a83c2c4eb8505f3869ae34a0fc0c99faad8d09441a4b6c25957878bae0986a06210370c6"
        "2b5825253b3aa11eaad"
        "33de17707635ab8b3d3da6adf4e3476975cbf31c7034730450221009d863d536461b33c2f32a57f20eae9bd753"
        "a90c3ce03861711c83a"
        "3e84acc140022079f5b9b8e3919e78f5810fa896b657c4c60b42a87d03d0ec69b3a2b325a6d2d201010102208e"
        "bdf68f9b0039c3a1694"
        "5c547926f52cc579fe083f04e1e8f47dfb4567408d5062102550febeeac572b026ff35005d7eac961d022d6da0"
        "b3dfc09b5dd9497069b"
        "6efb01010211320407436861726c696506210217840122f107299ce042275fa54aa7160dce2cc30927adb98724"
        "7a1154ac66af0104000"
        "00001129a051074fe5d7c6dc5f4bf6e1c9377c8af5af50540c23c37399d369c34d27aed791fefadf0c5f3f577a"
        "b435e5c0484bcc51173"
        "16f74e757cf544cb3d8ab1ea4aed6143e6d4efe15256b9687c67c274abd4677649a006210217840122f107299c"
        "e042275fa54aa7160dc"
        "e2cc30927adb987247a1154ac66af062102051214c6e9a39f2e2e84628bbc3f9e34535efbaa54209618b86fc38"
        "68ddd70740346304402"
        "20080a6ee6461ba97aa20e90cbd532b0ae7bef3978ce0c3237b4e6d20af7770b92022060f2f614156cc29cc3ae"
        "428f4aef38e163a1be9"
        "250a642799bfa2e43a88373bc";

    const int expected_block_count = 3;

    const char* expected_issuers[] = {
        "02550febeeac572b026ff35005d7eac961d022d6da0b3dfc09b5dd9497069b6efb",
        "02550febeeac572b026ff35005d7eac961d022d6da0b3dfc09b5dd9497069b6efb",
        "02550febeeac572b026ff35005d7eac961d022d6da0b3dfc09b5dd9497069b6efb"};

    const char* expected_parents[] = {
        "ab9565de221ab57423a4b395e0db36bfe451a11394a62b8c347bf89ac78cd967",
        "e0434c11beed87a586c57d5068bc59ec076b707a2ea280c9ea44cf1f618c7053",
        "8ebdf68f9b0039c3a16945c547926f52cc579fe083f04e1e8f47dfb4567408d5"};

    const char* expected_signatures[] = {
        "3044022040a9f6b3ca8b7aab0260bc53bc5d544597cb92ab8d4736c17f5fc990137a6e0202205e4fa3f21cdce0"
        "16fdfbbc1ea3c6e78c"
        "136594e4e8068ac5b2cccb4e7d0ac8c6",

        "30450221009d863d536461b33c2f32a57f20eae9bd753a90c3ce03861711c83a3e84acc140022079f5b9b8e391"
        "9e78f5810fa896b657"
        "c4c60b42a87d03d0ec69b3a2b325a6d2d2",

        "30440220080a6ee6461ba97aa20e90cbd532b0ae7bef3978ce0c3237b4e6d20af7770b92022060f2f614156cc2"
        "9cc3ae428f4aef38e"
        "163a1be9250a642799bfa2e43a88373bc"};

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);
    int block_index = 0;

    while (buffer_can_read(&buffer, 2)) {
        // Parse block header
        block_header_t header;
        parse_block_header(&buffer, &header);

        // Check issuer
        char issuer_hex[65];
        atohex(header.issuer, sizeof(header.issuer), issuer_hex);
        assert_string_equal(expected_issuers[block_index], issuer_hex);

        // Check parent
        char parent_hex[64];
        atohex(header.parent, sizeof(header.parent), parent_hex);
        assert_string_equal(expected_parents[block_index], parent_hex);

        // Parse commands
        for (int command_index = 0; command_index < header.length; command_index++) {
            printf("block_index: %d, command_index: %d\n", block_index, command_index);
            if (block_index == 0 && command_index == 0) {
                expected_seed_command_t expectations = {
                    .topic = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851",
                    .version = 0,
                    .ephemeral_public_key =
                        "03378aff702550fd188196e2a7731fc8f0958f31e47e85ae7c0d32b5137aee796e",
                    .xpriv =
                        "1fb8fd54a5d4e2cbc846a9d40ac770099bd95032d6db17edd3e38d6b2d8d883e3a9f6d4843"
                        "0ae4aa43"
                        "45ede589cb5651e179ad96b34481377749fa7c7f966ab5",
                    .group_key =
                        "03ab80381ce1f25cd242916bbbb99b3feb067fc49f9844ed167d28dda567ae04b6",
                    .iv = "0d1cb422e09eefe91f6766630c0f95fe"};
                assert_seed_command(&buffer, &expectations, NULL);
            } else if (block_index == 1 && command_index == 0) {
                expected_add_member_t expectations = {
                    .name = "Bob",
                    .permissions = 1,
                    .public_key =
                        "0318a83c2c4eb8505f3869ae34a0fc0c99faad8d09441a4b6c25957878bae0986a"};
                assert_add_member_command(&buffer, &expectations, NULL);
            } else if (block_index == 1 && command_index == 1) {
                expected_publish_key_t expectations = {
                    .recipient =
                        "0318a83c2c4eb8505f3869ae34a0fc0c99faad8d09441a4b6c25957878bae0986a",
                    .encrypted_key =
                        "0db0d57c70f7b263ea4c90fd9f9f5da743a046c03e8c8ac3991283dbf3bb0629ac8038b1be"
                        "1638dda9b"
                        "d3a7aab2a1c8eac82365bdebe73a353096ae3a09470e3",
                    .ephemeral_public_key =
                        "0370c62b5825253b3aa11eaad33de17707635ab8b3d3da6adf4e3476975cbf31c7",
                    .initialization_vector = "1659b1d3706ea17c56061e118e970494"};
                assert_publish_key_command(&buffer, &expectations, NULL);
            } else if (block_index == 2 && command_index == 0) {
                expected_add_member_t expectations = {
                    .name = "Charlie",
                    .permissions = 1,
                    .public_key =
                        "0217840122f107299ce042275fa54aa7160dce2cc30927adb987247a1154ac66af"};
                assert_add_member_command(&buffer, &expectations, NULL);
            } else if (block_index == 2 && command_index == 1) {
                expected_publish_key_t expectations = {
                    .encrypted_key =
                        "c23c37399d369c34d27aed791fefadf0c5f3f577ab435e5c0484bcc5117316f74e757cf544"
                        "cb3d8ab1ea4ae"
                        "d6143e6d4efe15256b9687c67c274abd4677649a0",
                    .ephemeral_public_key =
                        "02051214c6e9a39f2e2e84628bbc3f9e34535efbaa54209618b86fc3868ddd7074",
                    .recipient =
                        "0217840122f107299ce042275fa54aa7160dce2cc30927adb987247a1154ac66af",
                    .initialization_vector = "74fe5d7c6dc5f4bf6e1c9377c8af5af5",
                };
                assert_publish_key_command(&buffer, &expectations, NULL);
            }
        }

        // Parse signature
        uint8_t signature[MAX_DER_SIG_LEN];
        int sig_size = parse_block_signature(&buffer, signature, sizeof(signature));

        // Check signature
        char signature_hex[MAX_DER_SIG_LEN * 2];
        memset(signature_hex, 0, sizeof(signature_hex));
        atohex(signature, sig_size, signature_hex);
        assert_string_equal(expected_signatures[block_index], signature_hex);

        // Increment block index
        block_index += 1;
    }

    assert_int_equal(block_index, expected_block_count);

    free((void*) buffer.ptr);
}

static void test_parse_derive_command(void** state) {
    (void) state;
    const char* command = "";
    // TODO: implement
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_block_header_parse),
                                       cmocka_unit_test(test_block_commands_parse),
                                       cmocka_unit_test(test_stream_parse),
                                       cmocka_unit_test(test_parse_derive_command)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
