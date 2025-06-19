// src/security/encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <stddef.h> // For size_t

#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

/**
 * @brief Fills a buffer with cryptographically secure random bytes.
 * @param buffer The buffer to fill.
 * @param num_bytes The number of bytes to generate.
 * @return 0 on success, -1 on failure.
 */
int encryption_generate_random_bytes(uint8_t* buffer, size_t num_bytes);

/**
 * @brief Encrypts data using AES-256 GCM.
 * @param plaintext The data to encrypt.
 * @param plaintext_len The length of the plaintext.
 * @param key The 256-bit AES encryption key.
 * @param iv The 12-byte IV.
 * @param ciphertext_buffer A pointer to a pointer where the address of the newly allocated
 * ciphertext buffer will be stored. The caller is responsible for freeing it.
 * @param tag The 16-byte authentication tag.
 * @return The length of the ciphertext on success, or -1 on error.
 */
// MODIFIED SIGNATURE FOR INTERNAL ALLOCATION
int encryption_encrypt_aes_gcm(const uint8_t* plaintext, int plaintext_len,
                               const uint8_t key[AES_256_KEY_SIZE], const uint8_t iv[AES_GCM_IV_SIZE],
                               uint8_t** ciphertext_buffer, // <<< --- THIS IS THE CRITICAL CHANGE
                               uint8_t tag[AES_GCM_TAG_SIZE]);


/**
 * @brief Decrypts data using AES-256 GCM.
 * @param ciphertext The encrypted data.
 * @param ciphertext_len The length of the ciphertext.
 * @param key The 256-bit AES decryption key.
 * @param iv The 12-byte IV.
 * @param tag The 16-byte authentication tag.
 * @param plaintext_buffer A pointer to a pointer where the address of the newly allocated
 * plaintext buffer will be stored. The caller is responsible for freeing it.
 * @return The length of the plaintext on success, or -1 on error (e.g., authentication failure).
 */
int encryption_decrypt_aes_gcm(const uint8_t* ciphertext, int ciphertext_len,
                               const uint8_t key[AES_256_KEY_SIZE], const uint8_t iv[AES_GCM_IV_SIZE],
                               const uint8_t tag[AES_GCM_TAG_SIZE],
                               uint8_t** plaintext_buffer); // <<< --- Also likely needs to be pointer to pointer for consistency

#endif // ENCRYPTION_H
