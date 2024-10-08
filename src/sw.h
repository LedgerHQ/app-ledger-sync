#pragma once

/**
 * Status word for success.
 */
#define SW_OK 0x9000
/**
 * Status word for Command code not supported.
 */
#define SW_CMD_CODE_NOT_SUPPORTED 0x911C
/**
 * Status word for denied by user.
 */
#define SW_DENY 0x6985
/**
 * Status word for wrong data.
 */
#define SW_WRONG_DATA 0x6A80
/**
 * Status word for incorrect P1 or P2.
 */
#define SW_WRONG_P1P2 0x6A86
/**
 * Status word for either wrong Lc or length of APDU command less than 5.
 */
#define SW_WRONG_DATA_LENGTH 0x6A87
/**
 * Status word for unknown command with this INS.
 */
#define SW_INS_NOT_SUPPORTED 0x6D00
/**
 * Status word for instruction class is different than CLA.
 */
#define SW_CLA_NOT_SUPPORTED 0x6E00
/**
 * Status word for wrong response length (buffer too small or too big).
 */
#define SW_WRONG_RESPONSE_LENGTH 0xB000
/**
 * Status word for fail to display BIP32 path.
 */
#define SW_DISPLAY_BIP32_PATH_FAIL 0xB001
/**
 * Status word for fail to display address.
 */
#define SW_DISPLAY_ADDRESS_FAIL 0xB002
/**
 * Status word for fail to display amount.
 */
#define SW_DISPLAY_AMOUNT_FAIL 0xB003
/**
 * Status word for wrong transaction length.
 */
#define SW_WRONG_TX_LENGTH 0xB004
/**
 * Status word for fail of transaction parsing.
 */
#define SW_TX_PARSING_FAIL 0xB005
/**
 * Status word for fail of transaction hash.
 */
#define SW_TX_HASH_FAIL 0xB006
/**
 * Status word for bad state.
 */
#define SW_BAD_STATE 0xB007
/**
 * Status word for signature fail.
 */
#define SW_SIGNATURE_FAIL 0xB008
/**
 * Status for fail to parse stream due to inconsistent state.
 */
#define SW_STREAM_PARSER_BAD_STATE 0xB009
/**
 * Status for fail to parse stream due to invalid format.
 */
#define SW_STREAM_PARSER_INVALID_FORMAT 0xB00A

/**
 * Status for buffer overflow (for trusted property).
 */
#define SW_TP_BUFFER_OVERFLOW 0xB00B

/**
 * Status for fail when the stream is closed
 */
#define SW_STREAM_CLOSED 0xB00C

/**
 * Status for fail to parse due to invalid format.
 */
#define SW_PARSER_INVALID_FORMAT 0xB00D

/**
 * Status for fail to parse due to invalid format.
 */
#define SW_PARSER_INVALID_VALUE 0xB00E

/**
 * Status for fail to parse due to invalid format.
 */
#define SW_CHALLENGE_NOT_VERIFIED 0xB00F
