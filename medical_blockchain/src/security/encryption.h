// src/security/encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <stddef.h> // For size_t

// AES-256 GCM constants
#define AES_256_KEY_SIZE 32 // 256 bits
#define AES_GCM_IV_SIZE  12 // GCM recommended IV size
#define AES_GCM_TAG_SIZE 16 // GCM authentication tag size

/**
 * @brief Encrypts data using AES-256 GCM with OpenSSL.
 *
 * @param plaintext The data to be encrypted.
 * @param plaintext_len The length of the plaintext data.
 * @param key The 32-byte (AES-256) encryption key.
 * @param iv The 12-byte initialization vector (IV).
 * @param ciphertext_buffer A buffer to store the encrypted data. Must be large enough
 * (plaintext_len + AES_GCM_TAG_SIZE).
 * @param tag_buffer A buffer to store the 16-byte authentication tag.
 * @return The actual length of the ciphertext on success, -1 on failure.
 */
int encryption_encrypt_aes_gcm(
    const uint8_t *plaintext,
    int plaintext_len,
    const uint8_t *key,
    const uint8_t *iv,
    uint8_t *ciphertext_buffer,
    uint8_t *tag_buffer
);

/**
 * @brief Decrypts data using AES-256 GCM with OpenSSL.
 *
 * @param ciphertext The encrypted data.
 * @param ciphertext_len The length of the ciphertext data.
 * @param key The 32-byte (AES-256) encryption key.
 * @param iv The 12-byte initialization vector (IV).
 * @param tag The 16-byte authentication tag.
 * @param plaintext_buffer A buffer to store the decrypted data. Must be large enough
 * (ciphertext_len - AES_GCM_TAG_SIZE).
 * @return The actual length of the plaintext on success, -1 on failure (e.g., authentication failure).
 */
int encryption_decrypt_aes_gcm(
    const uint8_t *ciphertext,
    int ciphertext_len,
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *tag,
    uint8_t *plaintext_buffer
);

/**
 * @brief Generates cryptographically secure random bytes for keys or IVs.
 * @param buffer The buffer to fill with random bytes.
 * @param num_bytes The number of bytes to generate.
 * @return 0 on success, -1 on failure.
 */
int encryption_generate_random_bytes(uint8_t *buffer, size_t num_bytes);


#endif // ENCRYPTION_H
