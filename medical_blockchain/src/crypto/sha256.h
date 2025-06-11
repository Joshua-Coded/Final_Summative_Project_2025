// src/crypto/sha256.h
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h> // For uint8_t, size_t

// Define the size of a SHA256 hash in bytes
// OpenSSL's SHA256_DIGEST_LENGTH is 32 bytes.
#define SHA256_DIGEST_LENGTH 32

/**
 * @brief Computes the SHA256 hash of a given data buffer.
 * @param data The input data buffer.
 * @param len The length of the input data.
 * @param output_hash A buffer to store the 32-byte (256-bit) hash.
 * Must be at least SHA256_DIGEST_LENGTH bytes.
 */
void sha256(const uint8_t *data, size_t len, uint8_t *output_hash);

/**
 * @brief Computes the SHA256 hash of a given string and converts it to a hexadecimal string.
 * @param input_string The input string.
 * @param output_hex_string A buffer to store the 64-character hexadecimal hash string (plus null terminator).
 * Must be at least 65 bytes (2 * SHA256_DIGEST_LENGTH + 1).
 */
void sha256_hex_string(const char *input_string, char *output_hex_string);

#endif // SHA256_H
