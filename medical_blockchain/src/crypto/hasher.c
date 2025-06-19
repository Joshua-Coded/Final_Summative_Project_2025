// src/crypto/hasher.c
#include "hasher.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../utils/logger.h"

/**
 * @brief Computes the SHA256 hash of a given data block.
 */
int hasher_sha256(const uint8_t* data, size_t len, uint8_t* output_hash) {
    if (data == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for hasher_sha256: data or output_hash is NULL.");
        return -1;
    }

    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "EVP_MD_CTX_new failed for SHA256.");
        return -1;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestInit_ex failed for SHA256.");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, len)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestUpdate failed for SHA256.");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, output_hash, &md_len)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestFinal_ex failed for SHA256.");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (md_len != SHA256_DIGEST_LENGTH) {
        logger_log(LOG_LEVEL_WARN, "Unexpected SHA256 digest length: %u bytes (expected %u).", md_len, SHA256_DIGEST_LENGTH);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

/**
 * @brief Converts a byte array to its hexadecimal string representation (dynamically allocated).
 */
char* hasher_bytes_to_hex(const uint8_t* bytes, size_t len) {
    if (bytes == NULL || len == 0) {
        char* empty_str = (char*)malloc(1);
        if (empty_str) *empty_str = '\0';
        return empty_str;
    }

    char* hex_string = (char*)malloc(len * 2 + 1);
    if (hex_string == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_string[i * 2], "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0';
    return hex_string;
}

/**
 * @brief Converts a byte array to its hexadecimal string representation into a provided buffer.
 */
void hasher_bytes_to_hex_buf(const uint8_t* bytes, size_t len, char* hex_buf, size_t buf_len) {
    if (hex_buf == NULL || bytes == NULL || buf_len < (len * 2 + 1)) {
        if (hex_buf != NULL && buf_len > 0) {
            hex_buf[0] = '\0';
        }
        logger_log(LOG_LEVEL_ERROR, "Invalid input or buffer too small for hasher_bytes_to_hex_buf.");
        return;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_buf[i * 2], "%02x", bytes[i]);
    }
    hex_buf[len * 2] = '\0';
}

/**
 * @brief Converts a hexadecimal string to a byte array into a provided buffer.
 */
int hasher_hex_to_bytes_buf(const char *hex_str, uint8_t *byte_buf, size_t byte_buf_len) {
    if (hex_str == NULL || byte_buf == NULL) {
        logger_log(LOG_LEVEL_ERROR, "hasher_hex_to_bytes_buf: Input hex_str or byte_buf is NULL.");
        return -1;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        logger_log(LOG_LEVEL_ERROR, "hasher_hex_to_bytes_buf: Hex string length is odd.");
        return -1; // Hex string must have an even length
    }

    size_t expected_byte_len = hex_len / 2;
    if (byte_buf_len < expected_byte_len) {
        logger_log(LOG_LEVEL_ERROR, "hasher_hex_to_bytes_buf: Output buffer too small. Expected %zu, got %zu.", expected_byte_len, byte_buf_len);
        return -1; // Output buffer too small
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned int byte_val;
        if (sscanf(&hex_str[i], "%2x", &byte_val) != 1) {
            logger_log(LOG_LEVEL_ERROR, "hasher_hex_to_bytes_buf: Invalid hex character found at position %zu.", i);
            return -1; // Invalid hex character
        }
        byte_buf[i / 2] = (uint8_t)byte_val;
    }

    return 0; // Success
}

/**
 * @brief Initializes the SHA256 hashing context for streaming operations.
 */
int hasher_sha256_stream_init(EVP_MD_CTX* ctx) {
    if (ctx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for hasher_sha256_stream_init: ctx is NULL. Must be allocated by EVP_MD_CTX_new().");
        return -1;
    }
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestInit_ex failed in hasher_sha256_stream_init.");
        return -1;
    }
    return 0;
}

/**
 * @brief Updates the SHA256 hash with a new chunk of data.
 */
int hasher_sha256_stream_update(EVP_MD_CTX* ctx, const uint8_t* data, size_t len) {
    if (ctx == NULL || data == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for hasher_sha256_stream_update: ctx or data is NULL.");
        return -1;
    }
    if (1 != EVP_DigestUpdate(ctx, data, len)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestUpdate failed for SHA256.");
        return -1;
    }
    return 0;
}

/**
 * @brief Finalizes the SHA256 hash calculation and retrieves the result.
 */
int hasher_sha256_stream_final(EVP_MD_CTX* ctx, uint8_t* hash) {
    if (ctx == NULL || hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for hasher_sha256_stream_final: ctx or hash is NULL.");
        return -1;
    }
    unsigned int md_len;
    if (1 != EVP_DigestFinal_ex(ctx, hash, &md_len)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestFinal_ex failed in hasher_sha256_stream_final.");
        return -1;
    }
    if (md_len != SHA256_DIGEST_LENGTH) {
        logger_log(LOG_LEVEL_WARN, "hasher_sha256_stream_final: Unexpected digest length (%u, expected %u).", md_len, SHA256_DIGEST_LENGTH);
        return -1;
    }
    return 0;
}
