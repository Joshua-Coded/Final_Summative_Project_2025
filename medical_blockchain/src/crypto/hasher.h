// src/crypto/hasher.h
#ifndef HASHER_H
#define HASHER_H

#include <stdint.h> // For uint8_t
#include <stddef.h> // For size_t

#define SHA256_HASH_SIZE 32
#define HASH_HEX_LEN (SHA256_HASH_SIZE * 2) // Length of hex characters without null terminator

/**
 * @brief Computes the SHA256 hash of an input buffer.
 * @param input A pointer to the input data.
 * @param input_len The length of the input data in bytes.
 * @param output_hash A buffer of SHA256_HASH_SIZE bytes to store the raw binary hash.
 * @return void (does not return a status, assumes success if buffers are valid)
 */
void hasher_sha256(const uint8_t* input, size_t input_len, uint8_t* output_hash);

/**
 * @brief Converts a byte array to its hexadecimal string representation.
 * @param bytes The byte array.
 * @param len The length of the byte array.
 * @return A dynamically allocated string containing the hex representation,
 * or NULL on allocation failure. Caller must free the string.
 */
char* hasher_bytes_to_hex(const uint8_t* bytes, size_t len);

/**
 * @brief Converts a byte array to its hexadecimal string representation into a provided buffer.
 * @param bytes The byte array.
 * @param len The length of the byte array.
 * @param hex_buf A buffer to store the hex string representation.
 * @param buf_len The size of the provided buffer (must be at least len * 2 + 1).
 * @return void (does not return a status, performs the conversion or writes empty string on error)
 */
void hasher_bytes_to_hex_buf(const uint8_t* bytes, size_t len, char* hex_buf, size_t buf_len);

#endif // HASHER_H
