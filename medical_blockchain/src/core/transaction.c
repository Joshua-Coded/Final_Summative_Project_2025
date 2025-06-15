// src/core/transaction.c
#include "transaction.h"
#include "../crypto/hasher.h" // For SHA256 and SHA256_HEX_LEN, SHA256_HASH_SIZE
#include "../utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../security/encryption.h" // For encryption functions and constants

/**
 * @brief Calculates the hash of a transaction.
 * This is crucial for verifying transaction integrity and inclusion in blocks.
 * The hash includes all fields *except* the signature and transaction_id itself.
 * The transaction_id is derived from this hash.
 * This function will now hash the ENCRYPTED medical data.
 * @param tx A pointer to the Transaction.
 * @param output_hash A buffer to store the resulting SHA256 hash (SHA256_HASH_SIZE bytes).
 * @return 0 on success, -1 on failure.
 */
int transaction_calculate_hash(const Transaction* tx, uint8_t* output_hash) { // CHANGE type here
    if (tx == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_calculate_hash: tx or output_hash is NULL.");
        return -1;
    }

    // Buffer to concatenate transaction data for hashing
    // Estimate max size: sender_id + recipient_id + encrypted_medical_data + IV + Tag + timestamp + value + delimiters
    // Assuming max string lengths as defined + fixed sizes
    // Adding extra buffer for numeric conversions (timestamp, value)
    size_t data_len = strlen(tx->sender_id) + strlen(tx->recipient_id) +
                      tx->encrypted_medical_data_len + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE +
                      100; // Generous space for timestamp, value, and delimiters/null terminator

    // IMPORTANT: When hashing binary data (like IV, Tag, encrypted_medical_data),
    // it's best to create a single `uint8_t` buffer and `memcpy` everything into it,
    // rather than trying to `snprintf` binary data. snprintf expects `char*` and
    // might treat null bytes as string terminators.
    uint8_t* data_to_hash_binary = (uint8_t*)malloc(data_len + 1); // +1 just in case, though not strictly needed for binary
    if (data_to_hash_binary == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for transaction data hashing.");
        return -1;
    }

    size_t current_offset = 0;

    // Copy string parts first (sender_id, recipient_id, timestamp, value)
    // Convert timestamp and value to string representations temporarily if hashing as string
    char temp_numeric_str[64]; // Buffer for timestamp and value
    int snp_res = snprintf(temp_numeric_str, sizeof(temp_numeric_str), "%s%s%ld%.4f",
                           tx->sender_id, tx->recipient_id, (long)tx->timestamp, tx->value);
    if (snp_res < 0 || (size_t)snp_res >= sizeof(temp_numeric_str)) {
        logger_log(LOG_LEVEL_ERROR, "Failed to format numeric/string part of transaction hash input.");
        free(data_to_hash_binary);
        return -1;
    }
    memcpy(data_to_hash_binary + current_offset, temp_numeric_str, snp_res);
    current_offset += snp_res;


    // Now append binary data directly
    if (tx->encrypted_medical_data && tx->encrypted_medical_data_len > 0) {
        if (current_offset + tx->encrypted_medical_data_len > data_len) {
            logger_log(LOG_LEVEL_ERROR, "Hash buffer too small for encrypted data."); free(data_to_hash_binary); return -1;
        }
        memcpy(data_to_hash_binary + current_offset, tx->encrypted_medical_data, tx->encrypted_medical_data_len);
        current_offset += tx->encrypted_medical_data_len;
    }

    if (current_offset + AES_GCM_IV_SIZE > data_len) { logger_log(LOG_LEVEL_ERROR, "Hash buffer too small for IV."); free(data_to_hash_binary); return -1; }
    memcpy(data_to_hash_binary + current_offset, tx->iv, AES_GCM_IV_SIZE);
    current_offset += AES_GCM_IV_SIZE;

    if (current_offset + AES_GCM_TAG_SIZE > data_len) { logger_log(LOG_LEVEL_ERROR, "Hash buffer too small for Tag."); free(data_to_hash_binary); return -1; }
    memcpy(data_to_hash_binary + current_offset, tx->tag, AES_GCM_TAG_SIZE);
    current_offset += AES_GCM_TAG_SIZE;

    // Finally, hash the concatenated binary data
    // The cast (const uint8_t*)data_to_hash is no longer needed if data_to_hash_binary is uint8_t*
    // FIX: Removed comparison to != 0, as hasher_sha256 returns void.
    hasher_sha256(data_to_hash_binary, current_offset, output_hash);

    free(data_to_hash_binary);
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
    memset(tx->signature, 0, sizeof(tx->signature)); // Now uint8_t array

    // Copy IDs (ensure they fit the buffer)
    strncpy(tx->sender_id, sender_id, MAX_ID_LENGTH);
    tx->sender_id[MAX_ID_LENGTH] = '\0';
    strncpy(tx->recipient_id, recipient_id, MAX_ID_LENGTH);
    tx->recipient_id[MAX_ID_LENGTH] = '\0';

    tx->timestamp = time(NULL);
    tx->value = value;

    // --- Encrypt medical_data ---
    int plaintext_len = strlen(medical_data);
    tx->encrypted_medical_data = (uint8_t*)malloc(plaintext_len); // Ciphertext has same length as plaintext in GCM
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
    // tx->transaction_id is now uint8_t*, so this assignment is direct and correct
    if (transaction_calculate_hash(tx, tx->transaction_id) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate transaction hash.");
        transaction_destroy(tx);
        return NULL;
    }

    // Convert binary transaction_id to hex string for logging
    char tx_id_hex[SHA256_HASH_SIZE * 2 + 1];
    // FIX: Added buf_len argument for hasher_bytes_to_hex_buf
    hasher_bytes_to_hex_buf(tx->transaction_id, SHA256_HASH_SIZE, tx_id_hex, sizeof(tx_id_hex));
    logger_log(LOG_LEVEL_DEBUG, "Transaction created: ID=%s, Sender=%s, Recipient=%s",
               tx_id_hex, tx->sender_id, tx->recipient_id);

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

    // Calculate the binary hash to sign
    uint8_t hash_to_sign_binary[SHA256_HASH_SIZE];
    if (transaction_calculate_hash(tx, hash_to_sign_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for signing.");
        return -1;
    }

    // Convert the hash to hex string if you need it in the 'temp_sig_input' string
    char hash_to_sign_hex[SHA256_HASH_SIZE * 2 + 1];
    // FIX: Added buf_len argument for hasher_bytes_to_hex_buf
    hasher_bytes_to_hex_buf(hash_to_sign_binary, SHA256_HASH_SIZE, hash_to_sign_hex, sizeof(hash_to_sign_hex));

    // Simplified placeholder: A "signature" derived from private_key and hash.
    // In a real system, this would be a complex cryptographic operation.
    char temp_sig_input[MAX_ID_LENGTH * 2 + SHA256_HASH_SIZE * 2 + 20]; // Rough size, more robust
    snprintf(temp_sig_input, sizeof(temp_sig_input), "%s_signed_with_%s_for_hash_%s",
             tx->sender_id, private_key, hash_to_sign_hex); // Use hex string for snprintf

    // Store the result of hasher_sha256 directly into tx->signature (which is now uint8_t*)
    // FIX: Removed comparison to != 0, as hasher_sha256 returns void.
    hasher_sha256((const uint8_t*)temp_sig_input, strlen(temp_sig_input), tx->signature);

    // For logging, convert the binary signature to hex
    char sig_hex_log[SHA256_HASH_SIZE * 2 + 1];
    // FIX: Added buf_len argument for hasher_bytes_to_hex_buf
    hasher_bytes_to_hex_buf(tx->signature, SHA256_HASH_SIZE, sig_hex_log, sizeof(sig_hex_log));

    logger_log(LOG_LEVEL_DEBUG, "Transaction %s signed with placeholder signature: %s.",
               hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE), sig_hex_log);
    return 0;
}

/**
 * @brief Verifies the signature of a transaction. (Placeholder - actual cryptographic verification needed)
 * @param tx A pointer to the Transaction to verify.
 * @param public_key A placeholder for the public key.
 * @return 0 on success (signature valid), -1 on failure (signature invalid).
 */
int transaction_is_valid(const Transaction* tx) { // Renamed from verify_signature to is_valid per common practice
    if (tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot validate a NULL transaction.");
        return -1;
    }

    // Recalculate the hash that should be stored as tx->transaction_id
    uint8_t recomputed_tx_id[SHA256_HASH_SIZE];
    if (transaction_calculate_hash(tx, recomputed_tx_id) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to recalculate transaction hash for validation of transaction %s.",
                   hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE));
        return -1;
    }

    // Compare recomputed hash with the stored transaction_id
    if (memcmp(tx->transaction_id, recomputed_tx_id, SHA256_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_WARN, "Transaction ID mismatch. Stored ID: %s, Recalculated ID: %s",
                           hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE),
                           hasher_bytes_to_hex(recomputed_tx_id, SHA256_HASH_SIZE));
        return -1;
    }

    // For the final project, you would also call transaction_verify_signature here
    // with the appropriate public key. For now, we'll assume valid if the hash matches.
    // if (transaction_verify_signature(tx, <public_key_here>) != 0) {
    //     logger_log(LOG_LEVEL_WARN, "Transaction signature verification failed for transaction %s.",
    //                hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE));
    //     return -1;
    // }

    logger_log(LOG_LEVEL_DEBUG, "Transaction %s is valid.", hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE));
    return 0;
}

// NOTE: The previous transaction_verify_signature function is still needed for signing,
// so I'm keeping it separate and renamed transaction_is_valid to be the comprehensive check.
// If transaction_is_valid is meant to *only* check the hash, then the signature verification
// might be called elsewhere (e.g., in a higher-level validation function).
// Given the project scope, I'll provide the previous `transaction_verify_signature`
// as a standalone function for the signing logic.

int transaction_verify_signature(const Transaction* tx, const char* public_key) {
    // Check for empty signature by inspecting its content (not string length)
    uint8_t zero_signature[SHA256_HASH_SIZE] = {0};
    if (tx == NULL || public_key == NULL || memcmp(tx->signature, zero_signature, SHA256_HASH_SIZE) == 0) {
        logger_log(LOG_LEVEL_WARN, "Cannot verify transaction: NULL or empty parameters/signature.");
        return -1; // Cannot verify if no signature or invalid inputs
    }

    // Calculate the binary hash that was originally signed
    uint8_t expected_hash_binary[SHA256_HASH_SIZE];
    if (transaction_calculate_hash(tx, expected_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for signature verification.");
        return -1;
    }

    // Convert expected hash to hex string for constructing the input string for re-hashing
    char expected_hash_hex[SHA256_HASH_SIZE * 2 + 1];
    // FIX: Added buf_len argument for hasher_bytes_to_hex_buf
    hasher_bytes_to_hex_buf(expected_hash_binary, SHA256_HASH_SIZE, expected_hash_hex, sizeof(expected_hash_hex));

    char temp_sig_input_expected[MAX_ID_LENGTH * 2 + SHA256_HASH_SIZE * 2 + 20]; // Match size with signing
    snprintf(temp_sig_input_expected, sizeof(temp_sig_input_expected), "%s_signed_with_%s_for_hash_%s",
             tx->sender_id, public_key, expected_hash_hex);

    // Recompute the signature hash (binary)
    uint8_t recomputed_signature[SHA256_HASH_SIZE];
    // FIX: Removed comparison to != 0, as hasher_sha256 returns void.
    hasher_sha256((const uint8_t*)temp_sig_input_expected, strlen(temp_sig_input_expected), recomputed_signature);

    // For verification, compare the binary signatures directly using memcmp
    if (memcmp(tx->signature, recomputed_signature, SHA256_HASH_SIZE) == 0) {
        logger_log(LOG_LEVEL_DEBUG, "Signature for transaction %s VERIFIED (placeholder).", hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE));
        return 0; // Valid
    } else {
        logger_log(LOG_LEVEL_WARN, "Signature for transaction %s FAILED verification (placeholder).", hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE));
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
    printf("  Transaction ID: %s\n", hasher_bytes_to_hex(tx->transaction_id, SHA256_HASH_SIZE)); // Convert to hex for printing
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
        }
    } else {
        printf("  Medical Data (Encrypted, decryption key not provided or data missing).\n");
    }

    printf("  Signature: %s\n", hasher_bytes_to_hex(tx->signature, SHA256_HASH_SIZE)); // Convert to hex for printing
}
