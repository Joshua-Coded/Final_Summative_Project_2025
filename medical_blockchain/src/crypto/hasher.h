// src/crypto/hasher.h
#ifndef HASHER_H
#define HASHER_H

#include <stdint.h> // For uint8_t
#include <stddef.h> // For size_t
#include "sha256.h" // Include sha256.h to get SHA256_HASH_SIZE, HASH_HEX_LEN, etc.
#include <openssl/evp.h> // Required for EVP_MD_CTX for streaming SHA256

// Note: SHA256_DIGEST_LENGTH and SHA256_HEX_LEN are assumed to be defined in sha256.h
// or equivalent. If not, define them here:
// #define SHA256_DIGEST_LENGTH 32 // 32 bytes for SHA256 hash
// #define SHA256_HEX_LEN (SHA256_DIGEST_LENGTH * 2) // 64 hex characters

/**
 * @brief Computes the SHA256 hash of an input buffer using a single call.
 * This is for cases where all data is available at once.
 * @param input A pointer to the input data.
 * @param input_len The length of the input data in bytes.
 * @param output_hash A buffer of SHA256_DIGEST_LENGTH bytes to store the raw binary hash.
 * @return void
 */
int hasher_sha256(const uint8_t* input, size_t input_len, uint8_t* output_hash);

/**
 * @brief Converts a byte array to its hexadecimal string representation.
 * Dynamically allocates memory for the string. Caller must free the returned string.
 * @param bytes The byte array.
 * @param len The length of the byte array.
 * @return A dynamically allocated string containing the hex representation,
 * or NULL on allocation failure.
 */
char* hasher_bytes_to_hex(const uint8_t* bytes, size_t len);

/**
 * @brief Converts a byte array to its hexadecimal string representation into a provided buffer.
 * Ensures null-termination. Caller must ensure buf_len is sufficient (at least len * 2 + 1).
 * @param bytes The byte array.
 * @param len The length of the byte array.
 * @param hex_buf A buffer to store the hex string representation.
 * @param buf_len The size of the provided buffer.
 * @return void
 */
void hasher_bytes_to_hex_buf(const uint8_t* bytes, size_t len, char* hex_buf, size_t buf_len);

// --- Streaming SHA256 functions using OpenSSL EVP API ---
// These allow hashing data in chunks.

/**
 * @brief Initializes the SHA256 hashing context for streaming operations.
 * @param ctx A pointer to an EVP_MD_CTX structure that will be initialized.
 */
int hasher_sha256_stream_init(EVP_MD_CTX* ctx);

/**
 * @brief Updates the SHA256 hash with a new chunk of data.
 * @param ctx A pointer to the initialized EVP_MD_CTX structure.
 * @param data The input data chunk.
 * @param len The length of the data chunk.
 */
int hasher_sha256_stream_update(EVP_MD_CTX* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalizes the SHA256 hash calculation and retrieves the result.
 * The context is cleaned up after finalization.
 * @param ctx A pointer to the initialized EVP_MD_CTX structure.
 * @param hash A buffer of SHA256_DIGEST_LENGTH bytes to store the final raw binary hash.
 */
int hasher_sha256_stream_final(EVP_MD_CTX* ctx, uint8_t* hash);

#endif // HASHER_H
