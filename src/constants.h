#pragma once

/**
 * Instruction class of the Trustchain application
 */
#define CLA 0xE0

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

/**
 * Hash length (bytes).
 */
#define HASH_LEN 32

/**
 * Length of the public key of a member
 */
#define MEMBER_KEY_LEN 33

/**
 * Max length of a group topic
 */
#define MAX_TOPIC_LEN 32

/**
 * Max length of a member name
 */
#define MAX_NAME_LEN 100

/**
 * Max encrypted key length
 */
#define MAX_ENCRYPTED_KEY_LEN 64

/**
 * Session encryption key length
 */
#define SESSION_ENCRYPTION_KEY_LEN 32

/**
 * Length of initialization vectors used for encryption
 */
#define IV_LEN 16

/*
 * Private key length
 */
#define PRIVATE_KEY_LEN 32

// TODO TO REMOVE instantiated in src/main.c

extern const uint32_t SEED_ID_PATH[2];
extern const size_t SEED_ID_PATH_LEN;