// src/security/encryption.c
#include "encryption.h"
#include "../utils/logger.h" // For logging
#include <openssl/evp.h>     // For EVP_Cipher functions
#include <openssl/rand.h>    // For RAND_bytes
#include <string.h>          // For memcpy
#include <stdio.h>           // For snprintf, if needed for debugging
#include <stdlib.h>          // For malloc, free

/**
 * @brief Encrypts data using AES-256 GCM with OpenSSL.
 *
 * @param plaintext The data to be encrypted.
 * @param plaintext_len The length of the plaintext data.
 * @param key The 32-byte (AES-256) encryption key.
 * @param iv The 12-byte initialization vector (IV).
 * @param ciphertext_buffer_ptr A pointer to a uint8_t* where the function will store the pointer to the newly allocated encrypted data.
 * The caller is responsible for freeing this memory.
 * @param tag_buffer A buffer to store the 16-byte authentication tag.
 * @return The actual length of the ciphertext on success, -1 on failure.
 */
int encryption_encrypt_aes_gcm(
    const uint8_t *plaintext,
    int plaintext_len,
    const uint8_t *key,
    const uint8_t *iv,
    uint8_t **ciphertext_buffer_ptr, // <<-- CHANGED TO DOUBLE POINTER
    uint8_t *tag_buffer
) {
    if (plaintext == NULL || plaintext_len < 0 || key == NULL || iv == NULL ||
        ciphertext_buffer_ptr == NULL || tag_buffer == NULL) { // <<-- CHECK ciphertext_buffer_ptr
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for encryption_encrypt_aes_gcm.");
        return -1;
    }

    // Set the pointer to NULL initially, in case of early exit or failure
    *ciphertext_buffer_ptr = NULL;

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len = 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        logger_log(LOG_LEVEL_ERROR, "EVP_CIPHER_CTX_new failed.");
        return -1;
    }

    // Initialize the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length (optional, but good practice if not default size)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_CTRL_GCM_SET_IVLEN failed.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_EncryptInit_ex (key/iv) failed.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Allocate memory for the ciphertext.
    // The maximum possible size for AES GCM ciphertext is plaintext_len.
    // However, OpenSSL functions might write slightly past `len` with `EncryptFinal_ex`,
    // so allocate `plaintext_len + AES_BLOCK_SIZE` for safety, though technically GCM
    // doesn't add padding. Let's use plaintext_len + AES_BLOCK_SIZE (16 bytes) for now.
    // Or even better, based on some examples, just `plaintext_len`.
    // Let's use `plaintext_len` as it's typically accurate for GCM, plus room for the tag if needed
    // (though tag is separate here).
    *ciphertext_buffer_ptr = (uint8_t*)malloc(plaintext_len);
    if (!*ciphertext_buffer_ptr) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for encrypted data.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide the plaintext, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext_buffer_ptr, &len, plaintext, plaintext_len)) { // <<-- DEREFERENCE HERE
        logger_log(LOG_LEVEL_ERROR, "EVP_EncryptUpdate failed.");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_buffer_ptr); // Clean up allocated memory
        *ciphertext_buffer_ptr = NULL;
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption. (For GCM, this primarily processes any AAD if used, and prepares for tag retrieval).
    // Note: For GCM, EncryptFinal_ex usually adds 0 bytes to the ciphertext if no AAD is involved,
    // but it's crucial for authentication to pass through.
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext_buffer_ptr + len, &len)) { // <<-- DEREFERENCE HERE
        logger_log(LOG_LEVEL_ERROR, "EVP_EncryptFinal_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_buffer_ptr); // Clean up allocated memory
        *ciphertext_buffer_ptr = NULL;
        return -1;
    }
    ciphertext_len += len; // Should typically be 0 for GCM here

    // Get the GCM authentication tag.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_buffer)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_CTRL_GCM_GET_TAG failed.");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_buffer_ptr); // Clean up allocated memory
        *ciphertext_buffer_ptr = NULL;
        return -1;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/**
 * @brief Decrypts data using AES-256 GCM with OpenSSL.
 *
 * @param ciphertext The encrypted data.
 * @param ciphertext_len The length of the ciphertext data.
 * @param key The 32-byte (AES-256) encryption key.
 * @param iv The 12-byte initialization vector (IV).
 * @param tag The 16-byte authentication tag.
 * @param plaintext_buffer_ptr A pointer to a uint8_t* where the function will store the pointer to the newly allocated decrypted plaintext.
 * The caller is responsible for freeing this memory.
 * @return The actual length of the plaintext on success, -1 on failure (e.g., authentication failure).
 */
int encryption_decrypt_aes_gcm(
    const uint8_t *ciphertext,
    int ciphertext_len,
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *tag,
    uint8_t **plaintext_buffer_ptr // <<-- THIS IS NOW A DOUBLE POINTER
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len_total = 0;
    int ret;

    if (ciphertext == NULL || ciphertext_len <= 0 || key == NULL || iv == NULL ||
        tag == NULL || plaintext_buffer_ptr == NULL) { // <<-- CHECK plaintext_buffer_ptr
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for encryption_decrypt_aes_gcm.");
        return -1;
    }

    // Set the pointer to NULL initially, in case of early exit or failure
    *plaintext_buffer_ptr = NULL;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        logger_log(LOG_LEVEL_ERROR, "EVP_CIPHER_CTX_new failed.");
        return -1;
    }

    // Initialize the decryption operation.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_CTRL_GCM_SET_IVLEN failed.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_DecryptInit_ex (key/iv) failed.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Allocate memory for the plaintext
    // A safe size for plaintext is ciphertext_len. Add +1 for null-terminator if you expect strings.
    *plaintext_buffer_ptr = (uint8_t*)malloc(ciphertext_len + 1); // <<-- ADDED MALLOC
    if (!*plaintext_buffer_ptr) { // <<-- CHECK ALLOCATION SUCCESS
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for decrypted data.");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    // Zero out the buffer before use, good practice
    memset(*plaintext_buffer_ptr, 0, ciphertext_len + 1);


    // Provide the ciphertext, and obtain the plaintext output.
    if (1 != EVP_DecryptUpdate(ctx, *plaintext_buffer_ptr, &len, ciphertext, ciphertext_len)) { // <<-- DEREFERENCE HERE
        logger_log(LOG_LEVEL_ERROR, "EVP_DecryptUpdate failed.");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_buffer_ptr); // <<-- FREE ON FAILURE
        *plaintext_buffer_ptr = NULL; // <<-- SET TO NULL ON FAILURE
        return -1;
    }
    plaintext_len_total = len;

    // Set the expected authentication tag.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag)) {
        logger_log(LOG_LEVEL_ERROR, "EVP_CTRL_GCM_SET_TAG failed.");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_buffer_ptr); // <<-- FREE ON FAILURE
        *plaintext_buffer_ptr = NULL; // <<-- SET TO NULL ON FAILURE
        return -1;
    }

    // Finalize the decryption. This checks the authentication tag.
    // If authentication fails, EVP_DecryptFinal_ex returns 0.
    ret = EVP_DecryptFinal_ex(ctx, *plaintext_buffer_ptr + plaintext_len_total, &len); // <<-- DEREFERENCE HERE

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success
        plaintext_len_total += len;
        // Null-terminate the decrypted data if it's expected to be a string
        (*plaintext_buffer_ptr)[plaintext_len_total] = '\0'; // <<-- NULL-TERMINATE
        return plaintext_len_total;
    } else {
        // Failure (e.g., authentication tag mismatch or other decryption error)
        logger_log(LOG_LEVEL_WARN, "Authentication failed during AES-GCM decryption! Data may be tampered or key/IV/tag is incorrect.");
        // Free the allocated memory on failure, if it was allocated
        if (*plaintext_buffer_ptr) { // Check if it's not NULL before freeing
            free(*plaintext_buffer_ptr);
            *plaintext_buffer_ptr = NULL; // Ensure it's NULL after freeing
        }
        return -1;
    }
}

/**
 * @brief Generates cryptographically secure random bytes for keys or IVs.
 * @param buffer The buffer to fill with random bytes.
 * @param num_bytes The number of bytes to generate.
 * @return 0 on success, -1 on failure.
 */
int encryption_generate_random_bytes(uint8_t *buffer, size_t num_bytes) {
    if (buffer == NULL || num_bytes == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for encryption_generate_random_bytes.");
        return -1;
    }

    if (RAND_bytes(buffer, num_bytes) != 1) {
        logger_log(LOG_LEVEL_ERROR, "RAND_bytes failed to generate random bytes.");
        // Depending on OpenSSL configuration, you might need to seed the PRNG,
        // but RAND_bytes is usually self-seeding on modern OS.
        return -1;
    }
    return 0;
}
