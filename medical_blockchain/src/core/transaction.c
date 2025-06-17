#include "transaction.h"
#include "../crypto/hasher.h" // For hasher_sha256, hasher_bytes_to_hex, SHA256_DIGEST_LENGTH, SHA256_HEX_LEN
#include "../security/encryption.h" // For AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_256_KEY_SIZE
#include "../utils/logger.h"
#include "../utils/colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/evp.h> // Explicitly include this to ensure full EVP_MD_CTX definition

// Helper to get transaction type string for logging/printing
static const char* get_transaction_type_string(TransactionType type) {
    switch (type) {
        case TX_NEW_RECORD: return "TX_NEW_RECORD";
        case TX_REQUEST_ACCESS: return "TX_REQUEST_ACCESS";
        case TX_GRANT_ACCESS: return "TX_GRANT_ACCESS";
        case TX_REVOKE_ACCESS: return "TX_REVOKE_ACCESS";
        default: return "UNKNOWN_TYPE";
    }
}

/**
 * @brief Creates a new transaction.
 * @param type The type of transaction.
 * @param sender_public_key_hash Hex string of sender's public key hash.
 * @param signature Hex string of the transaction's signature.
 * @return A pointer to the newly created Transaction, or NULL on failure.
 */
Transaction* transaction_create(TransactionType type,
                                 const char sender_public_key_hash[SHA256_HEX_LEN + 1],
                                 const char signature[SHA256_HEX_LEN * 2 + 1]) {
    if (sender_public_key_hash == NULL || signature == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_create: sender_public_key_hash or signature is NULL.");
        return NULL;
    }

    Transaction* tx = (Transaction*)calloc(1, sizeof(Transaction)); // Use calloc to zero-initialize
    if (tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for new transaction.");
        return NULL;
    }

    tx->type = type;
    tx->timestamp = time(NULL);

    strncpy(tx->sender_public_key_hash, sender_public_key_hash, SHA256_HEX_LEN);
    tx->sender_public_key_hash[SHA256_HEX_LEN] = '\0';

    strncpy(tx->signature, signature, SHA256_HEX_LEN * 2);
    tx->signature[SHA256_HEX_LEN * 2] = '\0';

    // The transaction ID will be calculated after setting specific data and signing.
    tx->transaction_id[0] = '\0';

    logger_log(LOG_LEVEL_DEBUG, "Transaction structure created for type: %s", get_transaction_type_string(type));

    return tx;
}

/**
 * @brief Adds new medical record data to a TX_NEW_RECORD transaction.
 * @param tx The transaction of type TX_NEW_RECORD.
 * @param encrypted_data The encrypted medical data (dynamically allocated).
 * @param encrypted_data_len Length of the encrypted data.
 * @param iv The IV used for encryption.
 * @param tag The GCM tag generated during encryption.
 * @param original_record_hash The SHA256 hex hash of the original unencrypted data.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_new_record_data(Transaction* tx,
                                     uint8_t* encrypted_data, size_t encrypted_data_len,
                                     const uint8_t iv[AES_GCM_IV_SIZE],
                                     const uint8_t tag[AES_GCM_TAG_SIZE],
                                     const char original_record_hash[SHA256_HEX_LEN + 1]) {
    if (tx == NULL || tx->type != TX_NEW_RECORD || encrypted_data == NULL || original_record_hash == NULL ||
        encrypted_data_len == 0 || iv == NULL || tag == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_set_new_record_data or transaction type mismatch.");
        return -1;
    }

    // Free any existing data if this function is called multiple times on the same tx
    if (tx->data.new_record.encrypted_data != NULL) {
        free(tx->data.new_record.encrypted_data);
    }

    tx->data.new_record.encrypted_data = (uint8_t*)malloc(encrypted_data_len);
    if (tx->data.new_record.encrypted_data == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for encrypted data.");
        return -1;
    }
    memcpy(tx->data.new_record.encrypted_data, encrypted_data, encrypted_data_len);
    tx->data.new_record.encrypted_data_len = encrypted_data_len;

    memcpy(tx->data.new_record.iv, iv, AES_GCM_IV_SIZE);
    memcpy(tx->data.new_record.tag, tag, AES_GCM_TAG_SIZE);

    strncpy(tx->data.new_record.original_record_hash, original_record_hash, SHA256_HEX_LEN);
    tx->data.new_record.original_record_hash[SHA256_HEX_LEN] = '\0';

    // Note: Transaction ID calculation and signing are typically done *after* all data is set
    // You'd call transaction_sign() after setting all the data for the transaction.
    // The current placement calculates the ID here, but the signature is set by transaction_sign.

    logger_log(LOG_LEVEL_DEBUG, "New record data set for transaction (ID will be set on signing). Encrypted data length: %zu", encrypted_data_len);
    return 0;
}

/**
 * @brief Sets data for access control transactions (TX_REQUEST_ACCESS, TX_GRANT_ACCESS, TX_REVOKE_ACCESS).
 * @param tx The transaction.
 * @param related_record_hash The hex hash of the medical record this transaction pertains to.
 * @param target_user_public_key_hash The hex hash of the public key of the user whose access is affected.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_access_control_data(Transaction* tx,
                                         const char related_record_hash[SHA256_HEX_LEN + 1],
                                         const char target_user_public_key_hash[SHA256_HEX_LEN + 1]) {
    if (tx == NULL || (tx->type != TX_REQUEST_ACCESS && tx->type != TX_GRANT_ACCESS && tx->type != TX_REVOKE_ACCESS) ||
        related_record_hash == NULL || target_user_public_key_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_set_access_control_data or transaction type mismatch.");
        return -1;
    }

    strncpy(tx->data.access_control.related_record_hash, related_record_hash, SHA256_HEX_LEN);
    tx->data.access_control.related_record_hash[SHA256_HEX_LEN] = '\0';

    strncpy(tx->data.access_control.target_user_public_key_hash, target_user_public_key_hash, SHA256_HEX_LEN);
    tx->data.access_control.target_user_public_key_hash[SHA256_HEX_LEN] = '\0';

    // Note: Transaction ID calculation and signing are typically done *after* all data is set
    // You'd call transaction_sign() after setting all the data for the transaction.

    logger_log(LOG_LEVEL_DEBUG, "Access control data set for transaction (ID will be set on signing).");
    return 0;
}

/**
 * @brief Calculates the hash of a transaction.
 * The transaction ID is the hash of its content.
 * @param tx A pointer to the transaction.
 * @param output_hash A buffer to store the calculated hash (SHA256_DIGEST_LENGTH bytes).
 * @return 0 on success, -1 on failure.
 */
int transaction_calculate_hash(Transaction* tx, uint8_t output_hash[SHA256_DIGEST_LENGTH]) {
    if (tx == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_calculate_hash: tx or output_hash is NULL.");
        return -1;
    }

    EVP_MD_CTX *ctx = NULL;

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create EVP_MD_CTX for transaction hash.");
        return -1;
    }

    hasher_sha256_stream_init(ctx);

    char data_buffer[1024]; // Use a reasonably sized buffer for string concatenation

    // Append type, timestamp, sender_public_key_hash
    int offset = snprintf(data_buffer, sizeof(data_buffer),
                          "%d%ld%s",
                          tx->type,
                          (long)tx->timestamp,
                          tx->sender_public_key_hash);

    if (offset < 0 || (size_t)offset >= sizeof(data_buffer)) {
        logger_log(LOG_LEVEL_ERROR, "Error or overflow during initial data formatting for transaction hash.");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    hasher_sha256_stream_update(ctx, (const uint8_t*)data_buffer, offset);

    // Append data specific to the transaction type
    switch (tx->type) {
        case TX_NEW_RECORD:
            offset = snprintf(data_buffer, sizeof(data_buffer),
                              "%s%zu",
                              tx->data.new_record.original_record_hash,
                              tx->data.new_record.encrypted_data_len);
            if (offset < 0 || (size_t)offset >= sizeof(data_buffer)) {
                logger_log(LOG_LEVEL_ERROR, "Error or overflow during new record payload data formatting for transaction hash.");
                EVP_MD_CTX_free(ctx);
                return -1;
            }
            hasher_sha256_stream_update(ctx, (const uint8_t*)data_buffer, offset);

            if (tx->data.new_record.encrypted_data != NULL && tx->data.new_record.encrypted_data_len > 0) {
                hasher_sha256_stream_update(ctx, tx->data.new_record.encrypted_data, tx->data.new_record.encrypted_data_len);
            } else {
                logger_log(LOG_LEVEL_WARN, "TX_NEW_RECORD has no encrypted data for hash calculation. This might be an error.");
            }
            hasher_sha256_stream_update(ctx, tx->data.new_record.iv, AES_GCM_IV_SIZE);
            hasher_sha256_stream_update(ctx, tx->data.new_record.tag, AES_GCM_TAG_SIZE);
            break;
        case TX_REQUEST_ACCESS:
        case TX_GRANT_ACCESS:
        case TX_REVOKE_ACCESS:
            offset = snprintf(data_buffer, sizeof(data_buffer),
                              "%s%s",
                              tx->data.access_control.related_record_hash,
                              tx->data.access_control.target_user_public_key_hash);
            if (offset < 0 || (size_t)offset >= sizeof(data_buffer)) {
                logger_log(LOG_LEVEL_ERROR, "Error or overflow during access control payload data formatting for transaction hash.");
                EVP_MD_CTX_free(ctx);
                return -1;
            }
            hasher_sha256_stream_update(ctx, (const uint8_t*)data_buffer, offset);
            break;
        default:
            logger_log(LOG_LEVEL_WARN, "Unknown transaction type (%d) during hash calculation. Payload not fully included.", tx->type);
            break;
    }

    hasher_sha256_stream_final(ctx, output_hash);
    EVP_MD_CTX_free(ctx);

    logger_log(LOG_LEVEL_DEBUG, "Transaction hash calculated for type %s.", get_transaction_type_string(tx->type));
    return 0;
}

/**
 * @brief Signs a transaction using a dummy mechanism.
 * In a real implementation, this would involve using the sender's private key
 * to sign the transaction's hash. This version calculates the transaction ID
 * and populates a dummy signature based on the transaction ID and a "private key" string.
 *
 * @param tx A pointer to the transaction to sign.
 * @param private_key_hex A placeholder for the private key (not actually used for crypto here,
 * but its string value influences the dummy signature).
 * @return 0 on success, -1 on failure.
 */
int transaction_sign(Transaction* tx, const char* private_key_hex) {
    if (tx == NULL || private_key_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for transaction_sign: tx or private_key_hex is NULL.");
        return -1;
    }

    uint8_t tx_data_hash_binary[SHA256_DIGEST_LENGTH];

    // The transaction_id is typically the hash of the *unsigned* transaction data.
    // Calculate the hash of the data that's being signed.
    if (transaction_calculate_hash(tx, tx_data_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate transaction data hash for signing.");
        return -1;
    }

    // Convert the binary hash to hex for the transaction ID
    char* tx_id_hex = hasher_bytes_to_hex(tx_data_hash_binary, SHA256_DIGEST_LENGTH);
    if (tx_id_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert transaction data hash to hex for ID.");
        return -1;
    }
    strncpy(tx->transaction_id, tx_id_hex, SHA256_HEX_LEN);
    tx->transaction_id[SHA256_HEX_LEN] = '\0';
    free(tx_id_hex); // Free the dynamically allocated hex string

    // --- DUMMY SIGNATURE GENERATION ---
    // In a real system, you would use a cryptographic library (like OpenSSL's ECDSA functions)
    // with an actual private key to sign the `tx_data_hash_binary`.
    // For demonstration, we'll create a reproducible "dummy" signature based on the
    // transaction ID and the provided "private_key_hex" string. This is NOT CRYPTOGRAPHICALLY SECURE.

    // Concatenate the "private key" and the transaction ID string for a deterministic dummy signature
    size_t concat_len = strlen(private_key_hex) + SHA256_HEX_LEN;
    char* data_to_sign_dummy = (char*)malloc(concat_len + 1);
    if (data_to_sign_dummy == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for dummy signature base.");
        return -1;
    }
    snprintf(data_to_sign_dummy, concat_len + 1, "%s%s", private_key_hex, tx->transaction_id);

    uint8_t dummy_signature_binary[SHA256_DIGEST_LENGTH];
    // This line had the error. Assuming hasher_sha256 returns int.
    if (hasher_sha256((const uint8_t*)data_to_sign_dummy, strlen(data_to_sign_dummy), dummy_signature_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash dummy signature base.");
        free(data_to_sign_dummy);
        return -1;
    }
    free(data_to_sign_dummy);

    char* dummy_signature_hex = hasher_bytes_to_hex(dummy_signature_binary, SHA256_DIGEST_LENGTH);
    if (dummy_signature_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert dummy signature hash to hex.");
        return -1;
    }

    // Copy the dummy signature into the transaction structure
    strncpy(tx->signature, dummy_signature_hex, SHA256_HEX_LEN * 2); // Use the full signature buffer size
    tx->signature[SHA256_HEX_LEN * 2] = '\0';
    free(dummy_signature_hex);

    logger_log(LOG_LEVEL_INFO, "Transaction %s signed (using dummy signature).", tx->transaction_id);
    return 0;
}

/**
 * @brief Verifies the signature of a transaction using a dummy mechanism.
 * This function checks if the dummy signature matches what would be generated
 * from the transaction ID and a hypothetical "private key" (which for this
 * dummy setup is just the string "CLI_PrivateKey_For_Signing_Tx").
 * In a real system, this would involve using the sender's public key
 * and the transaction hash to verify the cryptographic signature.
 *
 * @param tx A pointer to the transaction to verify.
 * @return true if the dummy signature is valid, false otherwise.
 */
bool transaction_verify_signature(const Transaction* tx) {
    if (tx == NULL || strlen(tx->transaction_id) == 0 || strlen(tx->signature) == 0 || strlen(tx->sender_public_key_hash) == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid transaction for signature verification: missing ID, signature, or sender key hash.");
        return false;
    }

    // Recompute the hash of the transaction data (this is what the signature is "over")
    uint8_t recomputed_tx_data_hash_binary[SHA256_DIGEST_LENGTH];
    // Cast away constness for transaction_calculate_hash as it modifies internal hash context
    // This cast is generally safe here because transaction_calculate_hash doesn't modify the
    // *content* of 'tx', only its internal hash state (the EVP_MD_CTX).
    if (transaction_calculate_hash((Transaction*)tx, recomputed_tx_data_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to recalculate transaction data hash for signature verification.");
        return false;
    }

    char* recomputed_tx_id_hex = hasher_bytes_to_hex(recomputed_tx_data_hash_binary, SHA256_DIGEST_LENGTH);
    if (recomputed_tx_id_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert recomputed transaction data hash to hex for verification.");
        return false;
    }

    // Compare recomputed transaction ID with stored transaction ID
    // The signature should be over this specific transaction ID
    if (strcmp(tx->transaction_id, recomputed_tx_id_hex) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Transaction ID mismatch during signature verification. Stored ID: %s, Recomputed ID: %s",
                   tx->transaction_id, recomputed_tx_id_hex);
        free(recomputed_tx_id_hex);
        return false;
    }
    free(recomputed_tx_id_hex);

    // --- DUMMY SIGNATURE VERIFICATION ---
    // Re-generate the expected dummy signature using the same logic as `transaction_sign`.
    // In a real scenario, you'd use the sender's public key to verify `tx->signature` against `tx_data_hash_binary`.

    const char* dummy_private_key_string = "CLI_PrivateKey_For_Signing_Tx"; // Must match the one used in transaction_sign

    size_t concat_len = strlen(dummy_private_key_string) + SHA256_HEX_LEN;
    char* expected_data_to_sign_dummy = (char*)malloc(concat_len + 1);
    if (expected_data_to_sign_dummy == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for expected dummy signature base.");
        return false;
    }
    snprintf(expected_data_to_sign_dummy, concat_len + 1, "%s%s", dummy_private_key_string, tx->transaction_id);

    uint8_t expected_dummy_signature_binary[SHA256_DIGEST_LENGTH];
    // This line had the error. Assuming hasher_sha256 returns int.
    if (hasher_sha256((const uint8_t*)expected_data_to_sign_dummy, strlen(expected_data_to_sign_dummy), expected_dummy_signature_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash expected dummy signature base during verification.");
        free(expected_data_to_sign_dummy);
        return false;
    }
    free(expected_data_to_sign_dummy);

    char* expected_dummy_signature_hex = hasher_bytes_to_hex(expected_dummy_signature_binary, SHA256_DIGEST_LENGTH);
    if (expected_dummy_signature_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert expected dummy signature hash to hex during verification.");
        return false;
    }

    bool is_valid = (strcmp(tx->signature, expected_dummy_signature_hex) == 0);
    if (!is_valid) {
        logger_log(LOG_LEVEL_WARN, "Dummy signature mismatch for transaction %s. Stored: %s, Expected: %s",
                   tx->transaction_id, tx->signature, expected_dummy_signature_hex);
    } else {
        logger_log(LOG_LEVEL_DEBUG, "Dummy signature verified successfully for transaction %s.", tx->transaction_id);
    }

    free(expected_dummy_signature_hex);
    return is_valid;
}


/**
 * @brief Verifies the integrity and validity of a transaction.
 * This might include verifying signatures, data consistency, etc.
 * @param tx A pointer to the transaction to verify.
 * @return 0 if the transaction is valid, -1 otherwise.
 */
int transaction_is_valid(const Transaction* tx) {
    if (tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot validate a NULL transaction.");
        return -1;
    }

    // 1. Check for valid transaction ID by recalculating
    uint8_t recomputed_tx_hash_binary[SHA256_DIGEST_LENGTH];
    // Cast away constness for transaction_calculate_hash as it modifies internal hash context
    // This cast is generally safe here because transaction_calculate_hash doesn't modify the
    // *content* of 'tx', only its internal hash state (the EVP_MD_CTX).
    if (transaction_calculate_hash((Transaction*)tx, recomputed_tx_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to recalculate hash for transaction %s during validation.", tx->transaction_id);
        return -1;
    }
    char* recomputed_tx_id_hex = hasher_bytes_to_hex(recomputed_tx_hash_binary, SHA256_DIGEST_LENGTH);
    if (!recomputed_tx_id_hex) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert recomputed hash to hex string.");
        return -1;
    }

    if (strcmp(tx->transaction_id, recomputed_tx_id_hex) != 0) {
        logger_log(LOG_LEVEL_WARN, "Transaction ID mismatch. Stored: %s, Recalculated: %s",
                   tx->transaction_id, recomputed_tx_id_hex);
        free(recomputed_tx_id_hex); // Free the allocated string
        return -1;
    }
    free(recomputed_tx_id_hex); // Free the allocated string

    // 2. Verify signature using the new dedicated function
    if (!transaction_verify_signature(tx)) {
        logger_log(LOG_LEVEL_ERROR, "Transaction %s: Signature verification failed.", tx->transaction_id);
        return -1;
    }

    // 3. Basic checks on sender public key hash
    if (strlen(tx->sender_public_key_hash) == 0) {
        logger_log(LOG_LEVEL_WARN, "Transaction %s has empty sender public key hash.", tx->transaction_id);
        return -1;
    }

    // Add more validation logic as needed based on transaction type
    switch (tx->type) {
        case TX_NEW_RECORD:
            if (tx->data.new_record.encrypted_data == NULL || tx->data.new_record.encrypted_data_len == 0 ||
                strlen(tx->data.new_record.original_record_hash) == 0) {
                logger_log(LOG_LEVEL_WARN, "TX_NEW_RECORD data is incomplete for transaction %s.", tx->transaction_id);
                return -1;
            }
            // Add validation for IV/Tag if needed
            break;
        case TX_REQUEST_ACCESS:
        case TX_GRANT_ACCESS:
        case TX_REVOKE_ACCESS:
            if (strlen(tx->data.access_control.related_record_hash) == 0 ||
                strlen(tx->data.access_control.target_user_public_key_hash) == 0) {
                logger_log(LOG_LEVEL_WARN, "Access control data is incomplete for transaction %s.", tx->transaction_id);
                return -1;
            }
            break;
        default:
            logger_log(LOG_LEVEL_WARN, "Unknown transaction type (%d) encountered during validation.", tx->type);
            break;
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction %s is valid.", tx->transaction_id);
    return 0;
}

/**
 * @brief Frees all memory allocated for a transaction.
 * @param tx A pointer to the transaction to destroy.
 */
void transaction_destroy(Transaction* tx) {
    if (tx == NULL) {
        return;
    }
    // Free dynamically allocated members within the union
    if (tx->type == TX_NEW_RECORD && tx->data.new_record.encrypted_data != NULL) {
        free(tx->data.new_record.encrypted_data);
        tx->data.new_record.encrypted_data = NULL;
    }
    free(tx);
    logger_log(LOG_LEVEL_DEBUG, "Transaction destroyed.");
}


/**
 * @brief Prints the details of a transaction to the console.
 * @param tx A pointer to the transaction to print.
 * @param encryption_key The key used for decryption if the transaction contains encrypted data (e.g., TX_NEW_RECORD).
 * Pass NULL if no decryption is needed or key is unavailable.
 */
void transaction_print(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]) {
    if (tx == NULL) {
        printf(ANSI_COLOR_RED "NULL Transaction\n" ANSI_COLOR_RESET);
        return;
    }
    printf(ANSI_COLOR_BLUE "--- Transaction Details ---\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "  Transaction ID:          " ANSI_COLOR_RESET "%s\n", tx->transaction_id);
    printf(ANSI_COLOR_BLUE "  Type:                    " ANSI_COLOR_RESET "%s (%d)\n", get_transaction_type_string(tx->type), tx->type);
    printf(ANSI_COLOR_BLUE "  Sender Public Key Hash:" ANSI_COLOR_RESET "%s\n", tx->sender_public_key_hash);
    // Corrected ctime usage by casting to time_t*
    printf(ANSI_COLOR_BLUE "  Timestamp:               " ANSI_COLOR_RESET "%ld (" ANSI_COLOR_BRIGHT_BLACK "%s" ANSI_COLOR_RESET ")", (long)tx->timestamp, ctime((const time_t*)&tx->timestamp)); // ctime adds newline

    printf(ANSI_COLOR_MAGENTA "  Payload: \n" ANSI_COLOR_RESET);
    switch (tx->type) {
        case TX_NEW_RECORD:
            printf(ANSI_COLOR_MAGENTA "    Encrypted Data Length: %zu\n" ANSI_COLOR_RESET, tx->data.new_record.encrypted_data_len);
            printf(ANSI_COLOR_MAGENTA "    Original Record Hash:  %s\n" ANSI_COLOR_RESET, tx->data.new_record.original_record_hash);
            printf(ANSI_COLOR_MAGENTA "    IV (hex):              " ANSI_COLOR_RESET);
            for (size_t i = 0; i < AES_GCM_IV_SIZE; ++i) {
                printf("%02x", tx->data.new_record.iv[i]);
            }
            printf("\n");
            printf(ANSI_COLOR_MAGENTA "    Tag (hex):             " ANSI_COLOR_RESET);
            for (size_t i = 0; i < AES_GCM_TAG_SIZE; ++i) {
                printf("%02x", tx->data.new_record.tag[i]);
            }
            printf("\n");

            if (encryption_key != NULL && tx->data.new_record.encrypted_data != NULL) {
                // Placeholder for decryption logic
                logger_log(LOG_LEVEL_INFO, "Attempting to decrypt medical record data (not implemented here).");
                // uint8_t* decrypted_data = NULL;
                // size_t decrypted_data_len = 0;
                // if (decrypt_data(encryption_key, tx->data.new_record.iv, tx->data.new_record.tag,
                //                  tx->data.new_record.encrypted_data, tx->data.new_record.encrypted_data_len,
                //                  &decrypted_data, &decrypted_data_len) == 0) {
                //    printf(ANSI_COLOR_GREEN "    Decrypted Data (partial): %.*s...\n" ANSI_COLOR_RESET,
                //           (int)(decrypted_data_len > 100 ? 100 : decrypted_data_len), decrypted_data);
                //    free(decrypted_data);
                // } else {
                //    logger_log(LOG_LEVEL_WARN, "Failed to decrypt medical record data.");
                // }
            }
            break;
        case TX_REQUEST_ACCESS:
        case TX_GRANT_ACCESS:
        case TX_REVOKE_ACCESS:
            printf(ANSI_COLOR_MAGENTA "    Related Record Hash:     %s\n" ANSI_COLOR_RESET, tx->data.access_control.related_record_hash);
            printf(ANSI_COLOR_MAGENTA "    Target User Key Hash:    %s\n" ANSI_COLOR_RESET, tx->data.access_control.target_user_public_key_hash);
            break;
        default:
            printf(ANSI_COLOR_MAGENTA "    No specific payload details for this type or unknown type.\n" ANSI_COLOR_RESET);
            break;
    }

    printf(ANSI_COLOR_BLUE "  Signature:               " ANSI_COLOR_RESET "%s\n", tx->signature);
    printf(ANSI_COLOR_BLUE "--------------------------------------------------\n" ANSI_COLOR_RESET);
}

// Serialization and Deserialization functions remain placeholders as they are complex
// and depend on your exact binary format requirements for network/disk storage.

/**
 * @brief Placeholder for serialization - very basic, needs to handle union correctly
 * This function is a minimal placeholder. Proper serialization needs to
 * handle all fields, including the union, in a defined binary format.
 * For now, we'll just serialize key string fields for demonstration.
 * A robust solution would use a library or manual packed binary format.
 * @param tx A pointer to the Transaction.
 * @param size A pointer to store the size of the serialized data.
 * @return A pointer to the serialized data, or NULL on failure.
 */
uint8_t* transaction_serialize(const Transaction* tx, size_t* size) {
    if (!tx) {
        *size = 0;
        return NULL;
    }

    // Estimate size for a simple byte copy (not truly robust for variable data)
    size_t total_size = sizeof(Transaction);
    if (tx->type == TX_NEW_RECORD && tx->data.new_record.encrypted_data_len > 0) {
        // Account for the dynamically allocated encrypted_data
        total_size += tx->data.new_record.encrypted_data_len;
    }

    uint8_t* buffer = (uint8_t*)malloc(total_size);
    if (!buffer) {
        *size = 0;
        return NULL;
    }

    // This is a naive copy. A real serialization should be explicit about byte order,
    // string lengths, and union content.
    memcpy(buffer, tx, sizeof(Transaction));

    // For TX_NEW_RECORD, append the encrypted data if present
    if (tx->type == TX_NEW_RECORD && tx->data.new_record.encrypted_data != NULL) {
        memcpy(buffer + sizeof(Transaction), tx->data.new_record.encrypted_data, tx->data.new_record.encrypted_data_len);
    }

    *size = total_size;

    logger_log(LOG_LEVEL_DEBUG, "Transaction serialized (placeholder). Size: %zu", *size);
    return buffer;
}

/**
 * @brief Placeholder for deserialization
 * This function is a minimal placeholder. Proper deserialization needs to
 * reconstruct the Transaction struct from a defined binary format,
 * handling variable-length data and union members correctly.
 * @param data A pointer to the serialized data.
 * @param size The size of the serialized data.
 * @return A pointer to the deserialized Transaction, or NULL on failure.
 */
Transaction* transaction_deserialize(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(Transaction)) {
        return NULL;
    }

    Transaction* tx = (Transaction*)malloc(sizeof(Transaction));
    if (!tx) return NULL;

    // This is a naive copy. A real deserialization should be explicit about byte order,
    // string lengths, and union content.
    memcpy(tx, data, sizeof(Transaction));

    // Handle dynamically allocated encrypted_data for TX_NEW_RECORD
    if (tx->type == TX_NEW_RECORD && tx->data.new_record.encrypted_data_len > 0) {
        size_t expected_total_size = sizeof(Transaction) + tx->data.new_record.encrypted_data_len;
        if (size < expected_total_size) {
            logger_log(LOG_LEVEL_ERROR, "Deserialization error: Incomplete data for TX_NEW_RECORD.");
            free(tx);
            return NULL;
        }
        tx->data.new_record.encrypted_data = (uint8_t*)malloc(tx->data.new_record.encrypted_data_len);
        if (tx->data.new_record.encrypted_data == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Deserialization error: Failed to allocate memory for encrypted data.");
            free(tx);
            return NULL;
        }
        memcpy(tx->data.new_record.encrypted_data, data + sizeof(Transaction), tx->data.new_record.encrypted_data_len);
    } else {
        tx->data.new_record.encrypted_data = NULL; // Ensure it's NULL if not a new record or no data
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction deserialized (placeholder).");
    return tx;
}
