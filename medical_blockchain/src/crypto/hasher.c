// src/crypto/hasher.c
#include "hasher.h"
#include <openssl/sha.h>     // Still needed for SHA256_DIGEST_LENGTH constant if not defined elsewhere
#include <openssl/evp.h>     // For EVP_MD_CTX functions (modern OpenSSL hashing)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../utils/logger.h" // Assuming you have a logger for errors

/**
 * @brief Computes the SHA256 hash of a given data block using EVP API.
 * @param data The input data.
 * @param len The length of the input data.
 * @param output_hash A buffer to store the 32-byte SHA256 hash.
 */
void hasher_sha256(const uint8_t* data, size_t len, uint8_t* output_hash) {
    if (data == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for hasher_sha256: data or output_hash is NULL.");
        return; // For void return, just return on error
    }

    EVP_MD_CTX *mdctx; // Message Digest Context
    unsigned int md_len; // Length of the digest (should be SHA256_DIGEST_LENGTH)

    // Create a new context
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "EVP_MD_CTX_new failed for SHA256.");
        return;
    }

    // Initialize the context for SHA256 hashing
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestInit_ex failed for SHA256.");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Update the digest with the data
    if (1 != EVP_DigestUpdate(mdctx, data, len)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestUpdate failed for SHA256.");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Finalize the digest and get the hash
    if (1 != EVP_DigestFinal_ex(mdctx, output_hash, &md_len)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DigestFinal_ex failed for SHA256.");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Check if the hash length is as expected (32 bytes for SHA256)
    if (md_len != SHA256_DIGEST_LENGTH) {
        logger_log(LOG_LEVEL_WARN, "Unexpected SHA256 digest length: %u bytes (expected %u).", md_len, SHA256_DIGEST_LENGTH);
    }

    // Clean up the context
    EVP_MD_CTX_free(mdctx);
}

/**
 * @brief Converts a byte array to its hexadecimal string representation.
 * @param bytes The byte array.
 * @param len The length of the byte array.
 * @return A dynamically allocated string containing the hex representation,
 * or NULL on allocation failure. Caller must free the string.
 */
char* hasher_bytes_to_hex(const uint8_t* bytes, size_t len) {
    if (bytes == NULL || len == 0) {
        // Return an empty string or NULL if input is invalid
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
    hex_string[len * 2] = '\0'; // Null-terminate the string
    return hex_string;
}

/**
 * @brief Converts a byte array to its hexadecimal string representation into a provided buffer.
 * @param bytes The byte array.
 * @param len The length of the byte array.
 * @param hex_buf A buffer to store the hex string representation.
 * @param buf_len The size of the provided buffer (must be at least len * 2 + 1).
 */
void hasher_bytes_to_hex_buf(const uint8_t* bytes, size_t len, char* hex_buf, size_t buf_len) {
    if (hex_buf == NULL || bytes == NULL || buf_len < (len * 2 + 1)) {
        // Handle error: buffer too small or NULL input.
        // Ensure hex_buf is a valid pointer before attempting to write to it.
        if (hex_buf != NULL && buf_len > 0) {
            hex_buf[0] = '\0'; // Ensure it's an empty string if invalid input
        }
        return;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_buf[i * 2], "%02x", bytes[i]);
    }
    hex_buf[len * 2] = '\0'; // Null-terminate the string
}
