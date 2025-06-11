// src/core/transaction.c
#include "transaction.h"
#include "../crypto/hasher.h" // For SHA256 and SHA256_HEX_LEN
#include "../utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h> // For UUID generation for transaction_id
#include "../security/encryption.h" // For encryption functions and constants

// Function to generate a UUID (Universally Unique Identifier)
// Note: Requires libuuid development package (e.g., libuuid-dev on Ubuntu)
static void generate_uuid(char *buffer) {
    uuid_t b_uuid;
    uuid_generate_time(b_uuid); // Use time-based UUID for better uniqueness in a distributed system
    uuid_unparse_lower(b_uuid, buffer);
}

/**
 * @brief Calculates the hash of a transaction.
 * This is crucial for verifying transaction integrity and inclusion in blocks.
 * The hash includes all fields *except* the signature and transaction_id itself.
 * The transaction_id is derived from this hash.
 * This function will now hash the ENCRYPTED medical data.
 * @param tx A pointer to the Transaction.
 * @param output_hash A buffer to store the resulting SHA256 hash (SHA256_HEX_LEN + 1 bytes).
 * @return 0 on success, -1 on failure.
 */
int transaction_calculate_hash(const Transaction* tx, char* output_hash) {
    if (tx == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_calculate_hash: tx or output_hash is NULL.");
        return -1;
    }

    // Buffer to concatenate transaction data for hashing
    // Estimate max size: sender_id + recipient_id + encrypted_medical_data + IV + Tag + timestamp + value + delimiters
    // Assuming max string lengths as defined + fixed sizes
    size_t data_len = strlen(tx->sender_id) + strlen(tx->recipient_id) +
                      tx->encrypted_medical_data_len + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE +
                      64; // Generous space for timestamp, value, and delimiters

    char* data_to_hash = (char*)malloc(data_len + 1);
    if (data_to_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for transaction data hashing.");
        return -1;
    }

    // Format the data into a string for hashing.
    // Ensure all fixed-size and variable-length data is included in a consistent order.
    // The encrypted data, IV, and tag are binary, so we'll treat them as a raw byte sequence for hashing.
    // For string fields, we can include them as is.
    int offset = snprintf(data_to_hash, data_len + 1, "%s%s%ld%.4f",
                          tx->sender_id, tx->recipient_id, (long)tx->timestamp, tx->value);

    // Append the binary encrypted data, IV, and tag directly to the hash input
    if (offset < 0 || (size_t)offset >= data_len + 1) { // Check for snprintf error or truncation
        logger_log(LOG_LEVEL_ERROR, "Failed to format transaction string for hashing (initial part).");
        free(data_to_hash);
        return -1;
    }
    size_t current_len = (size_t)offset;

    if (tx->encrypted_medical_data && tx->encrypted_medical_data_len > 0) {
        if (current_len + tx->encrypted_medical_data_len > data_len) {
            logger_log(LOG_LEVEL_ERROR, "Hash buffer too small for encrypted data."); free(data_to_hash); return -1;
        }
        memcpy(data_to_hash + current_len, tx->encrypted_medical_data, tx->encrypted_medical_data_len);
        current_len += tx->encrypted_medical_data_len;
    }

    if (current_len + AES_GCM_IV_SIZE > data_len) { logger_log(LOG_LEVEL_ERROR, "Hash buffer too small for IV."); free(data_to_hash); return -1; }
    memcpy(data_to_hash + current_len, tx->iv, AES_GCM_IV_SIZE);
    current_len += AES_GCM_IV_SIZE;

    if (current_len + AES_GCM_TAG_SIZE > data_len) { logger_log(LOG_LEVEL_ERROR, "Hash buffer too small for Tag."); free(data_to_hash); return -1; }
    memcpy(data_to_hash + current_len, tx->tag, AES_GCM_TAG_SIZE);
    current_len += AES_GCM_TAG_SIZE;

    // Finally, hash the concatenated binary data
    if (hasher_sha256((const uint8_t*)data_to_hash, current_len, output_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "SHA256 hashing failed for transaction.");
        free(data_to_hash);
        return -1;
    }

    free(data_to_hash);
    return 0;
}


/**
 * @brief Creates a new transaction.
 * This function now encrypts the medical_data before storing it.
 *
 * @param sender_id Identifier of the sender.
 * @param recipient_id Identifier of the recipient.
 * @param medical_data The raw medical record data (plaintext) as a JSON string.
 * @param value The value associated with the transaction.
 * @param encryption_key The AES encryption key (32 bytes for AES-256).
 * @return A pointer to the newly created Transaction on success, NULL on failure.
 * The caller is responsible for freeing the transaction using transaction_destroy.
 */
Transaction* transaction_create(const char* sender_id, const char* recipient_id,
                                const char* medical_data, double value,
                                const uint8_t encryption_key[AES_256_KEY_SIZE]) {
    if (sender_id == NULL || recipient_id == NULL || medical_data == NULL || encryption_key == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_create: NULL parameters detected.");
        return NULL;
    }

    Transaction* tx = (Transaction*)malloc(sizeof(Transaction));
    if (tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for new transaction.");
        return NULL;
    }

    // Initialize pointers to NULL/0 for safety before potential early exit
    tx->encrypted_medical_data = NULL;
    tx->encrypted_medical_data_len = 0;
    memset(tx->iv, 0, AES_GCM_IV_SIZE);
    memset(tx->tag, 0, AES_GCM_TAG_SIZE);
    memset(tx->signature, 0, sizeof(tx->signature));


    // Copy IDs (ensure they fit the buffer)
    strncpy(tx->sender_id, sender_id, MAX_ID_LENGTH);
    tx->sender_id[MAX_ID_LENGTH] = '\0';
    strncpy(tx->recipient_id, recipient_id, MAX_ID_LENGTH);
    tx->recipient_id[MAX_ID_LENGTH] = '\0';

    tx->timestamp = time(NULL);
    tx->value = value;

    // --- Encrypt medical_data ---
    int plaintext_len = strlen(medical_data);
    // GCM can potentially expand data by up to tag size, but typically it's plaintext_len + tag_size
    // In GCM, ciphertext length is same as plaintext length. Tag is separate.
    int expected_ciphertext_len = plaintext_len;
    tx->encrypted_medical_data = (uint8_t*)malloc(expected_ciphertext_len); // Ciphertext has same length as plaintext in GCM
    if (tx->encrypted_medical_data == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for encrypted medical data.");
        transaction_destroy(tx);
        return NULL;
    }

    // Generate a new IV for this transaction
    if (encryption_generate_random_bytes(tx->iv, AES_GCM_IV_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate IV for medical data encryption.");
        transaction_destroy(tx);
        return NULL;
    }

    // Perform encryption
    int actual_ciphertext_len = encryption_encrypt_aes_gcm(
        (const uint8_t*)medical_data, plaintext_len,
        encryption_key, tx->iv,
        tx->encrypted_medical_data, tx->tag
    );

    if (actual_ciphertext_len == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to encrypt medical data.");
        transaction_destroy(tx);
        return NULL;
    }
    tx->encrypted_medical_data_len = actual_ciphertext_len;

    // Calculate initial transaction hash (before signing)
    if (transaction_calculate_hash(tx, tx->transaction_id) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate transaction hash.");
        transaction_destroy(tx);
        return NULL;
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction created: ID=%s, Sender=%s, Recipient=%s",
               tx->transaction_id, tx->sender_id, tx->recipient_id);

    return tx;
}

/**
 * @brief Destroys a transaction and frees its allocated memory.
 * This now includes freeing the dynamically allocated encrypted medical data.
 * @param tx A pointer to the Transaction to destroy.
 */
void transaction_destroy(Transaction* tx) {
    if (tx == NULL) {
        return;
    }
    if (tx->encrypted_medical_data != NULL) {
        free(tx->encrypted_medical_data);
        tx->encrypted_medical_data = NULL;
    }
    free(tx);
    logger_log(LOG_LEVEL_DEBUG, "Transaction destroyed.");
}


/**
 * @brief Signs a transaction. (Placeholder - actual cryptographic signing needed)
 * @param tx A pointer to the Transaction to sign.
 * @param private_key A placeholder for the private key.
 * @return 0 on success, -1 on failure.
 */
int transaction_sign(Transaction* tx, const char* private_key) {
    if (tx == NULL || private_key == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_sign.");
        return -1;
    }
    // Placeholder: In a real system, you'd use a crypto library (e.g., OpenSSL's ECDSA or RSA)
    // to sign the transaction's hash using the private_key.
    // The signature would be a fixed-size or known-max-size binary blob, typically Base64 or Hex encoded.
    // For now, we'll just copy a placeholder string.
    char hash_to_sign[SHA256_HEX_LEN + 1];
    if (transaction_calculate_hash(tx, hash_to_sign) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for signing.");
        return -1;
    }

    // Simplified placeholder: A "signature" derived from private_key and hash.
    // In a real system, this would be a complex cryptographic operation.
    char temp_sig_input[MAX_ID_LENGTH + SHA256_HEX_LEN + 10]; // Rough size
    snprintf(temp_sig_input, sizeof(temp_sig_input), "%s_signed_with_%s_for_hash_%s",
             tx->sender_id, private_key, hash_to_sign);

    hasher_sha256((const uint8_t*)temp_sig_input, strlen(temp_sig_input), tx->signature);
    logger_log(LOG_LEVEL_DEBUG, "Transaction %s signed with placeholder signature.", tx->transaction_id);
    return 0;
}

/**
 * @brief Verifies the signature of a transaction. (Placeholder - actual cryptographic verification needed)
 * @param tx A pointer to the Transaction to verify.
 * @param public_key A placeholder for the public key.
 * @return 0 on success (signature valid), -1 on failure (signature invalid).
 */
int transaction_verify_signature(const Transaction* tx, const char* public_key) {
    if (tx == NULL || public_key == NULL || strlen(tx->signature) == 0) {
        logger_log(LOG_LEVEL_WARN, "Cannot verify transaction: NULL or empty parameters.");
        return -1; // Cannot verify if no signature or invalid inputs
    }

    // Placeholder: In a real system, you'd use the corresponding crypto library (e.g., OpenSSL)
    // to verify the signature against the transaction's hash and the public_key.
    // The public key would be used to decrypt/verify the signature.
    char expected_hash[SHA256_HEX_LEN + 1];
    if (transaction_calculate_hash(tx, expected_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for signature verification.");
        return -1;
    }

    char temp_sig_input_expected[MAX_ID_LENGTH + SHA256_HEX_LEN + 10];
    snprintf(temp_sig_input_expected, sizeof(temp_sig_input_expected), "%s_signed_with_%s_for_hash_%s",
             tx->sender_id, public_key, expected_hash);

    char recomputed_signature[SHA256_HEX_LEN + 1];
    hasher_sha256((const uint8_t*)temp_sig_input_expected, strlen(temp_sig_input_expected), recomputed_signature);

    // For now, verification is just checking if recomputed matches stored placeholder signature.
    if (strcmp(tx->signature, recomputed_signature) == 0) {
        logger_log(LOG_LEVEL_DEBUG, "Signature for transaction %s VERIFIED (placeholder).", tx->transaction_id);
        return 0; // Valid
    } else {
        logger_log(LOG_LEVEL_WARN, "Signature for transaction %s FAILED verification (placeholder).", tx->transaction_id);
        return -1; // Invalid
    }
}

/**
 * @brief Decrypts the medical data of a transaction.
 * @param tx The transaction containing the encrypted medical data.
 * @param encryption_key The AES encryption key (32 bytes for AES-256).
 * @return A dynamically allocated string containing the decrypted plaintext on success, NULL on failure.
 * The caller is responsible for freeing this string.
 */
char* transaction_decrypt_medical_data(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]) {
    if (tx == NULL || encryption_key == NULL || tx->encrypted_medical_data == NULL || tx->encrypted_medical_data_len <= 0) {
        logger_log(LOG_LEVEL_ERROR, "Cannot decrypt medical data: Invalid transaction or key/data.");
        return NULL;
    }

    // Plaintext buffer size should be at least ciphertext_len (GCM does not add padding)
    uint8_t* plaintext_buffer = (uint8_t*)malloc(tx->encrypted_medical_data_len + 1); // +1 for null terminator
    if (plaintext_buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for decrypted medical data.");
        return NULL;
    }

    int decrypted_len = encryption_decrypt_aes_gcm(
        tx->encrypted_medical_data, tx->encrypted_medical_data_len,
        encryption_key, tx->iv, tx->tag,
        plaintext_buffer
    );

    if (decrypted_len == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to decrypt medical data (authentication failed or other error).");
        free(plaintext_buffer);
        return NULL;
    }

    plaintext_buffer[decrypted_len] = '\0'; // Null-terminate the decrypted string
    return (char*)plaintext_buffer;
}


/**
 * @brief Prints the details of a transaction.
 * @param tx A pointer to the Transaction to print.
 * @param encryption_key The AES encryption key (32 bytes for AES-256) needed for decryption, or NULL if not decrypting.
 */
void transaction_print(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]) {
    if (tx == NULL) {
        printf("NULL Transaction\n");
        return;
    }
    printf("  Transaction ID: %s\n", tx->transaction_id);
    printf("  Sender: %s\n", tx->sender_id);
    printf("  Recipient: %s\n", tx->recipient_id);
    printf("  Timestamp: %ld (%s)", (long)tx->timestamp, ctime(&tx->timestamp)); // ctime adds newline
    printf("  Value: %.4f\n", tx->value);

    // Attempt to decrypt and print medical data
    if (encryption_key != NULL && tx->encrypted_medical_data != NULL) {
        char* decrypted_data = transaction_decrypt_medical_data(tx, encryption_key);
        if (decrypted_data != NULL) {
            printf("  Medical Data (Decrypted): %s\n", decrypted_data);
            free(decrypted_data); // Free the dynamically allocated decrypted string
        } else {
            printf("  Medical Data (Encrypted, decryption failed).\n");
            // Optionally print raw encrypted data for debugging
            // printf("  Encrypted data (hex): ");
            // for (int i = 0; i < tx->encrypted_medical_data_len; i++) {
            //     printf("%02x", tx->encrypted_medical_data[i]);
            // }
            // printf("\n");
            // printf("  IV (hex): ");
            // for (int i = 0; i < AES_GCM_IV_SIZE; i++) {
            //     printf("%02x", tx->iv[i]);
            // }
            // printf("\n");
            // printf("  Tag (hex): ");
            // for (int i = 0; i < AES_GCM_TAG_SIZE; i++) {
            //     printf("%02x", tx->tag[i]);
            // }
            // printf("\n");
        }
    } else {
        printf("  Medical Data (Encrypted, decryption key not provided or data missing).\n");
    }

    printf("  Signature: %s\n", tx->signature);
}
