// src/crypto/sha256.h
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h> // For uint8_t
#include <stddef.h> // For size_t

// Core SHA256 constants
#define SHA256_DIGEST_LENGTH 32         // Size of the SHA256 hash in bytes
#define SHA256_HASH_SIZE SHA256_DIGEST_LENGTH // Alias for consistency
#define SHA256_HEX_LEN (SHA256_HASH_SIZE * 2) // Length of hex characters (64 for 32 bytes)
#define HASH_HEX_LEN SHA256_HEX_LEN     // General alias for hex hash length

/**
 * @brief Computes the SHA256 hash of a given data buffer.
 * @param data The input data buffer.
 * @param len The length of the input data.
 * @param output_hash A buffer to store the 32-byte (256-bit) hash.
 * Must be at least SHA256_DIGEST_LENGTH bytes.
 */
void sha256(const uint8_t *data, size_t len, uint8_t *output_hash);

/**
 * @brief Converts a raw byte array to its hexadecimal string representation.
 * @param bytes The input byte array.
 * @param len The length of the input byte array.
 * @param hex_string_output A buffer to store the hexadecimal string. Must be at least (len * 2 + 1) bytes.
 */
void bytes_to_hex_string(const uint8_t *bytes, size_t len, char *hex_string_output);

// This function seems to be for hashing a string and returning its hex string.
// If it's used, keep it. If hasher_sha256 covers this, you might consider removing it for simplicity.
void sha256_hex_string(const char *input_string, char *output_hex_string);

#endif // SHA256_H
