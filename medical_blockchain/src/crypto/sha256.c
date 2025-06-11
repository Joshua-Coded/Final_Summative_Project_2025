// src/crypto/sha256.c
#include "sha256.h"
#include <openssl/sha.h> // OpenSSL SHA256 header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Computes the SHA256 hash of a given data buffer using OpenSSL.
 * @param data The input data buffer.
 * @param len The length of the input data.
 * @param output_hash A buffer to store the 32-byte (256-bit) hash. Must be at least SHA256_DIGEST_LENGTH bytes.
 */
void sha256(const uint8_t *data, size_t len, uint8_t *output_hash) {
    if (data == NULL || output_hash == NULL) {
        // In a real application, you might log an error or handle this more robustly.
        // For simplicity, we'll just return.
        return;
    }

    // SHA256() is a convenience function provided by OpenSSL for one-shot hashing.
    // It takes the input data, its length, and an output buffer.
    SHA256(data, len, output_hash);
}

// Helper to convert byte array to hex string
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_string) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_string[i * 2], "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0';
}

/**
 * @brief Computes the SHA256 hash of a given string and converts it to a hexadecimal string.
 * @param input_string The input string.
 * @param output_hex_string A buffer to store the 64-character hexadecimal hash string (plus null terminator).
 * Must be at least 65 bytes (2 * SHA256_DIGEST_LENGTH + 1).
 */
void sha256_hex_string(const char *input_string, char *output_hex_string) {
    if (input_string == NULL || output_hex_string == NULL) {
        return;
    }

    uint8_t hash_bytes[SHA256_DIGEST_LENGTH]; // Use the OpenSSL-defined digest length
    sha256((const uint8_t*)input_string, strlen(input_string), hash_bytes);
    bytes_to_hex(hash_bytes, SHA256_DIGEST_LENGTH, output_hex_string);
}
