// src/crypto/hasher.h
#ifndef HASHER_H
#define HASHER_H

#include <stdint.h> // For uint8_t
#include <stddef.h> // For size_t
#include "sha256.h" // For SHA256_DIGEST_LENGTH, HASH_HEX_LEN
#include <openssl/evp.h> // For EVP_MD_CTX for streaming SHA256

int hasher_sha256(const uint8_t* input, size_t input_len, uint8_t* output_hash);
char* hasher_bytes_to_hex(const uint8_t* bytes, size_t len);
void hasher_bytes_to_hex_buf(const uint8_t* bytes, size_t len, char* hex_buf, size_t buf_len);
int hasher_hex_to_bytes_buf(const char *hex_str, uint8_t *byte_buf, size_t byte_buf_len); // Critical: Declaration of the missing function

// Streaming SHA256 functions using OpenSSL EVP API
int hasher_sha256_stream_init(EVP_MD_CTX* ctx);
int hasher_sha256_stream_update(EVP_MD_CTX* ctx, const uint8_t* data, size_t len);
int hasher_sha256_stream_final(EVP_MD_CTX* ctx, uint8_t* hash);

#endif // HASHER_H
