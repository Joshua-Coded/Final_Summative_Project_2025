// src/crypto/hasher.h (Example content)
#ifndef HASHER_H
#define HASHER_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_HEX_LEN 64 // SHA256 hash is 32 bytes, 64 hex characters

/**
 * @brief Computes the SHA256 hash of an input data buffer.
 * @param input The input data to hash.
 * @param input_len The length of the input data.
 * @param output_hash A buffer to store the resulting SHA256 hash as a hex string.
 * Must be at least SHA256_HEX_LEN + 1 bytes long.
 * @return 0 on success, -1 on failure.
 */
int hasher_sha256(const uint8_t* input, size_t input_len, char* output_hash);

#endif // HASHER_H
