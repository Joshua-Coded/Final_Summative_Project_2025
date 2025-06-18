#include "transaction.h"
#include "../crypto/hasher.h" // For hasher_sha256, hasher_bytes_to_hex, SHA256_DIGEST_LENGTH, SHA256_HEX_LEN
#include "../security/encryption.h" // For AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_256_KEY_SIZE
#include "../utils/logger.h"
#include "../utils/colors.h" // For ANSI_COLOR_* macros
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
 * @param signature Hex string of the transaction's signature. (Initial placeholder, will be updated by transaction_sign)
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

    // Ensure null-termination for fixed-size string arrays
    strncpy(tx->sender_public_key_hash, sender_public_key_hash, SHA256_HEX_LEN);
    tx->sender_public_key_hash[SHA256_HEX_LEN] = '\0'; // Explicit null-termination

    strncpy(tx->signature, signature, SHA256_HEX_LEN * 2);
    tx->signature[SHA256_HEX_LEN * 2] = '\0'; // Explicit null-termination

    // The transaction ID will be calculated after setting specific data and signing.
    tx->transaction_id[0] = '\0';

    // Initialize the union member pointer to NULL to prevent dangling pointers
    // This is crucial for TX_NEW_RECORD to prevent double-free or invalid free later
    if (type == TX_NEW_RECORD) {
        tx->data.new_record.encrypted_data = NULL;
        tx->data.new_record.encrypted_data_len = 0;
    }


    logger_log(LOG_LEVEL_DEBUG, "Transaction structure created for type: %s", get_transaction_type_string(type));

    return tx;
}

/**
 * @brief Adds new medical record data to a TX_NEW_RECORD transaction.
 * @param tx The transaction of type TX_NEW_RECORD.
 * @param encrypted_data The encrypted medical data (source buffer).
 * @param encrypted_data_len Length of the encrypted data.
 * @param iv The IV used for encryption.
 * @param tag The GCM tag generated during encryption.
 * @param original_record_hash The SHA256 hex hash of the original unencrypted data.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_new_record_data(Transaction* tx,
                                    const uint8_t* encrypted_data, size_t encrypted_data_len, // Changed to const uint8_t*
                                    const uint8_t iv[AES_GCM_IV_SIZE],
                                    const uint8_t tag[AES_GCM_TAG_SIZE],
                                    const char original_record_hash[SHA256_HEX_LEN + 1]) {
    if (tx == NULL || tx->type != TX_NEW_RECORD || encrypted_data == NULL || original_record_hash == NULL ||
        encrypted_data_len == 0 || iv == NULL || tag == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_set_new_record_data or transaction type mismatch.");
        return -1;
    }

    // Free any existing data to prevent memory leaks if this function is called multiple times on the same tx
    if (tx->data.new_record.encrypted_data != NULL) {
        free(tx->data.new_record.encrypted_data);
        tx->data.new_record.encrypted_data = NULL; // Set to NULL after freeing
    }

    // Allocate new memory for the encrypted data and copy it (DEEP COPY)
    tx->data.new_record.encrypted_data = (uint8_t*)malloc(encrypted_data_len);
    if (tx->data.new_record.encrypted_data == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for encrypted data in transaction.");
        return -1;
    }
    memcpy(tx->data.new_record.encrypted_data, encrypted_data, encrypted_data_len);
    tx->data.new_record.encrypted_data_len = encrypted_data_len;

    // Copy IV and Tag (fixed size arrays)
    memcpy(tx->data.new_record.iv, iv, AES_GCM_IV_SIZE);
    memcpy(tx->data.new_record.tag, tag, AES_GCM_TAG_SIZE);

    // Copy original_record_hash (fixed-size char array) and ensure null-termination
    strncpy(tx->data.new_record.original_record_hash, original_record_hash, SHA256_HEX_LEN);
    tx->data.new_record.original_record_hash[SHA256_HEX_LEN] = '\0'; // Explicit null-termination

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

    // Copy related_record_hash and ensure null-termination
    strncpy(tx->data.access_control.related_record_hash, related_record_hash, SHA256_HEX_LEN);
    tx->data.access_control.related_record_hash[SHA256_HEX_LEN] = '\0';

    // Copy target_user_public_key_hash and ensure null-termination
    strncpy(tx->data.access_control.target_user_public_key_hash, target_user_public_key_hash, SHA256_HEX_LEN);
    tx->data.access_control.target_user_public_key_hash[SHA256_HEX_LEN] = '\0';

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
int transaction_calculate_hash(const Transaction* tx, uint8_t output_hash[SHA256_DIGEST_LENGTH]) { // Added const to tx
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
            // The original_record_hash is also fixed size string.
            // No need to snprintf again; directly update.
            hasher_sha256_stream_update(ctx, (const uint8_t*)tx->data.new_record.original_record_hash, strlen(tx->data.new_record.original_record_hash));
            // Append length as well if it's part of the hash digest
            snprintf(data_buffer, sizeof(data_buffer), "%zu", tx->data.new_record.encrypted_data_len);
            hasher_sha256_stream_update(ctx, (const uint8_t*)data_buffer, strlen(data_buffer));


            if (tx->data.new_record.encrypted_data != NULL && tx->data.new_record.encrypted_data_len > 0) {
                hasher_sha256_stream_update(ctx, tx->data.new_record.encrypted_data, tx->data.new_record.encrypted_data_len);
            } else {
                // This warning should be an error if encrypted_data is mandatory for TX_NEW_RECORD
                logger_log(LOG_LEVEL_WARN, "TX_NEW_RECORD has no encrypted data for hash calculation. This might be an error.");
                // For a robust system, you might return -1 here. For now, just log.
            }
            hasher_sha256_stream_update(ctx, tx->data.new_record.iv, AES_GCM_IV_SIZE);
            hasher_sha256_stream_update(ctx, tx->data.new_record.tag, AES_GCM_TAG_SIZE);
            break;
        case TX_REQUEST_ACCESS:
        case TX_GRANT_ACCESS:
        case TX_REVOKE_ACCESS:
            // Access control data are fixed-size strings.
            hasher_sha256_stream_update(ctx, (const uint8_t*)tx->data.access_control.related_record_hash, strlen(tx->data.access_control.related_record_hash));
            hasher_sha256_stream_update(ctx, (const uint8_t*)tx->data.access_control.target_user_public_key_hash, strlen(tx->data.access_control.target_user_public_key_hash));
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
    // Copy to fixed-size array and ensure null-termination
    strncpy(tx->transaction_id, tx_id_hex, SHA256_HEX_LEN);
    tx->transaction_id[SHA256_HEX_LEN] = '\0';
    free(tx_id_hex); // Free the dynamically allocated hex string from hasher_bytes_to_hex

    // --- DUMMY SIGNATURE GENERATION ---
    // In a real system, you would use a cryptographic library (like OpenSSL's ECDSA functions)
    // with an actual private key to sign the `tx_data_hash_binary`.
    // For demonstration, we'll create a reproducible "dummy" signature based on the
    // transaction ID and the provided "private_key_hex" string. This is NOT CRYPTOGRAPHICALLY SECURE.

    // Concatenate the "private key" and the transaction ID string for a deterministic dummy signature
    // Make buffer large enough for both strings + null terminator
    size_t concat_len = strlen(private_key_hex) + strlen(tx->transaction_id);
    char* data_to_sign_dummy = (char*)malloc(concat_len + 1);
    if (data_to_sign_dummy == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for dummy signature base.");
        return -1;
    }
    snprintf(data_to_sign_dummy, concat_len + 1, "%s%s", private_key_hex, tx->transaction_id);

    uint8_t dummy_signature_binary[SHA256_DIGEST_LENGTH];
    // Check return value of hasher_sha256 (it returns int, 0 for success)
    if (hasher_sha256((const uint8_t*)data_to_sign_dummy, strlen(data_to_sign_dummy), dummy_signature_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash dummy signature base.");
        free(data_to_sign_dummy);
        return -1;
    }
    free(data_to_sign_dummy); // Free the temporary buffer

    char* dummy_signature_hex = hasher_bytes_to_hex(dummy_signature_binary, SHA256_DIGEST_LENGTH);
    if (dummy_signature_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert dummy signature hash to hex.");
        return -1;
    }

    // Copy the dummy signature into the transaction structure and ensure null-termination
    strncpy(tx->signature, dummy_signature_hex, SHA256_HEX_LEN * 2); // Use the full signature buffer size
    tx->signature[SHA256_HEX_LEN * 2] = '\0'; // Explicit null-termination
    free(dummy_signature_hex); // Free the dynamically allocated hex string

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
    if (transaction_calculate_hash(tx, recomputed_tx_data_hash_binary) != 0) { // Removed unnecessary cast, tx is const in this function
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

    // Make buffer large enough for both strings + null terminator
    size_t concat_len = strlen(dummy_private_key_string) + strlen(tx->transaction_id);
    char* expected_data_to_sign_dummy = (char*)malloc(concat_len + 1);
    if (expected_data_to_sign_dummy == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for expected dummy signature base.");
        return false;
    }
    snprintf(expected_data_to_sign_dummy, concat_len + 1, "%s%s", dummy_private_key_string, tx->transaction_id);

    uint8_t expected_dummy_signature_binary[SHA256_DIGEST_LENGTH];
    // Check return value of hasher_sha256 (it returns int, 0 for success)
    if (hasher_sha256((const uint8_t*)expected_data_to_sign_dummy, strlen(expected_data_to_sign_dummy), expected_dummy_signature_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash expected dummy signature base during verification.");
        free(expected_data_to_sign_dummy);
        return false;
    }
    free(expected_data_to_sign_dummy); // Free the temporary buffer

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

    free(expected_dummy_signature_hex); // Free the dynamically allocated hex string
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
    // Removed unnecessary const cast from (Transaction*)tx, tx is already const here.
    if (transaction_calculate_hash(tx, recomputed_tx_hash_binary) != 0) {
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
        logger_log(LOG_LEVEL_DEBUG, "Freeing encrypted data for TX_NEW_RECORD.");
        free(tx->data.new_record.encrypted_data);
        tx->data.new_record.encrypted_data = NULL; // Important: Set to NULL after freeing
    }
    // No need to free tx->sender_public_key_hash or tx->signature
    // because they are fixed-size arrays within the struct, not pointers to malloc'd memory.

    free(tx); // Free the transaction structure itself
    logger_log(LOG_LEVEL_DEBUG, "Transaction structure destroyed.");
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
    printf(ANSI_COLOR_BLUE "  Transaction ID:            " ANSI_COLOR_RESET "%s\n", tx->transaction_id);
    printf(ANSI_COLOR_BLUE "  Type:                      " ANSI_COLOR_RESET "%s (%d)\n", get_transaction_type_string(tx->type), tx->type);
    printf(ANSI_COLOR_BLUE "  Sender Public Key Hash:" ANSI_COLOR_RESET "%s\n", tx->sender_public_key_hash);
    printf(ANSI_COLOR_BLUE "  Timestamp:                 " ANSI_COLOR_RESET "%ld (" ANSI_COLOR_BRIGHT_BLACK "%s" ANSI_COLOR_RESET ")", (long)tx->timestamp, ctime((const time_t*)&tx->timestamp)); // ctime adds newline

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

            if (encryption_key != NULL && tx->data.new_record.encrypted_data != NULL && tx->data.new_record.encrypted_data_len > 0) {
                uint8_t* decrypted_data = NULL;
                int decrypted_data_len = 0; // Decryption functions usually return int for length or error

                decrypted_data_len = encryption_decrypt_aes_gcm(
                    tx->data.new_record.encrypted_data,
                    (int)tx->data.new_record.encrypted_data_len,
                    encryption_key,
                    tx->data.new_record.iv,
                    tx->data.new_record.tag,
                    &decrypted_data // Pass address to store malloc'd decrypted data
                );

                if (decrypted_data_len > 0 && decrypted_data != NULL) {
                    printf(ANSI_COLOR_GREEN "    Decrypted Data: %.*s\n" ANSI_COLOR_RESET,
                           decrypted_data_len, (char*)decrypted_data);
                    free(decrypted_data); // Free the memory allocated by decryption function
                } else {
                    logger_log(LOG_LEVEL_WARN, "Failed to decrypt medical record data for transaction %s (error code: %d).", tx->transaction_id, decrypted_data_len);
                    printf(ANSI_COLOR_RED "    Decryption failed or no data to decrypt.\n" ANSI_COLOR_RESET);
                }
            } else if (encryption_key == NULL) {
                printf(ANSI_COLOR_YELLOW "    (Medical data encrypted - pass --decrypt with key to attempt decryption)\n" ANSI_COLOR_RESET);
            } else {
                printf(ANSI_COLOR_YELLOW "    (No encrypted data or zero length for decryption.)\n" ANSI_COLOR_RESET);
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

    printf(ANSI_COLOR_BLUE "  Signature:                   " ANSI_COLOR_RESET "%s\n", tx->signature);
    printf(ANSI_COLOR_BLUE "--------------------------------------------------\n" ANSI_COLOR_RESET);
}

// --- Serialization and Deserialization functions ---

/**
 * @brief Serializes a transaction into a byte array.
 * This implementation aims to be more robust for `TX_NEW_RECORD` by handling
 * the dynamically allocated `encrypted_data`. It includes length prefixes
 * for variable-sized data.
 * @param tx A pointer to the Transaction.
 * @param size A pointer to store the size of the serialized data.
 * @return A pointer to the serialized data, or NULL on failure.
 */
uint8_t* transaction_serialize(const Transaction* tx, size_t* size) {
    if (!tx) {
        *size = 0;
        return NULL;
    }

    // Fixed-size part of the Transaction struct (excluding the union's dynamic data)
    // We'll manually serialize based on known sizes to handle padding, etc.
    // Assuming Transaction struct has: type, timestamp, sender_public_key_hash, transaction_id, signature.
    // This is a simplified approach, a real serialization would often define a precise protocol.
    size_t base_size = sizeof(tx->type) + sizeof(tx->timestamp) +
                       (SHA256_HEX_LEN + 1) + (SHA256_HEX_LEN + 1) + (SHA256_HEX_LEN * 2 + 1); // Add sizes of fixed arrays + null terminators

    size_t payload_size = 0;
    size_t encrypted_data_actual_len = 0; // To store actual length for TX_NEW_RECORD

    // Calculate payload size based on type
    if (tx->type == TX_NEW_RECORD) {
        payload_size += sizeof(tx->data.new_record.encrypted_data_len); // Store the length itself
        payload_size += AES_GCM_IV_SIZE;
        payload_size += AES_GCM_TAG_SIZE;
        payload_size += (SHA256_HEX_LEN + 1); // original_record_hash + null
        if (tx->data.new_record.encrypted_data != NULL) {
            encrypted_data_actual_len = tx->data.new_record.encrypted_data_len;
            payload_size += encrypted_data_actual_len;
        }
    } else if (tx->type == TX_REQUEST_ACCESS || tx->type == TX_GRANT_ACCESS || tx->type == TX_REVOKE_ACCESS) {
        payload_size += (SHA256_HEX_LEN + 1); // related_record_hash + null
        payload_size += (SHA256_HEX_LEN + 1); // target_user_public_key_hash + null
    }

    *size = base_size + payload_size;
    uint8_t* buffer = (uint8_t*)malloc(*size);
    if (!buffer) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for serialization buffer.");
        *size = 0;
        return NULL;
    }

    uint8_t* ptr = buffer;

    // Copy fixed fields
    memcpy(ptr, &tx->type, sizeof(tx->type));
    ptr += sizeof(tx->type);
    memcpy(ptr, &tx->timestamp, sizeof(tx->timestamp));
    ptr += sizeof(tx->timestamp);
    memcpy(ptr, tx->sender_public_key_hash, SHA256_HEX_LEN + 1); // Including null terminator
    ptr += (SHA256_HEX_LEN + 1);
    memcpy(ptr, tx->transaction_id, SHA256_HEX_LEN + 1); // Including null terminator
    ptr += (SHA256_HEX_LEN + 1);
    memcpy(ptr, tx->signature, SHA256_HEX_LEN * 2 + 1); // Including null terminator
    ptr += (SHA256_HEX_LEN * 2 + 1);

    // Copy payload based on type
    if (tx->type == TX_NEW_RECORD) {
        memcpy(ptr, &tx->data.new_record.encrypted_data_len, sizeof(tx->data.new_record.encrypted_data_len));
        ptr += sizeof(tx->data.new_record.encrypted_data_len);
        if (encrypted_data_actual_len > 0) {
            memcpy(ptr, tx->data.new_record.encrypted_data, encrypted_data_actual_len);
            ptr += encrypted_data_actual_len;
        }
        memcpy(ptr, tx->data.new_record.iv, AES_GCM_IV_SIZE);
        ptr += AES_GCM_IV_SIZE;
        memcpy(ptr, tx->data.new_record.tag, AES_GCM_TAG_SIZE);
        ptr += AES_GCM_TAG_SIZE;
        memcpy(ptr, tx->data.new_record.original_record_hash, SHA256_HEX_LEN + 1);
        ptr += (SHA256_HEX_LEN + 1);
    } else if (tx->type == TX_REQUEST_ACCESS || tx->type == TX_GRANT_ACCESS || tx->type == TX_REVOKE_ACCESS) {
        memcpy(ptr, tx->data.access_control.related_record_hash, SHA256_HEX_LEN + 1);
        ptr += (SHA256_HEX_LEN + 1);
        memcpy(ptr, tx->data.access_control.target_user_public_key_hash, SHA256_HEX_LEN + 1);
        ptr += (SHA256_HEX_LEN + 1);
    }

    return buffer;
}


/**
 * @brief Deserializes a byte array back into a Transaction structure.
 * This function must allocate memory for the Transaction and its dynamic members.
 * @param data The byte array containing the serialized transaction.
 * @param data_len The length of the byte array.
 * @return A pointer to the deserialized Transaction, or NULL on failure.
 */
Transaction* transaction_deserialize(const uint8_t* data, size_t data_len) {
    if (!data || data_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_deserialize: data is NULL or data_len is 0.");
        return NULL;
    }

    Transaction* tx = (Transaction*)calloc(1, sizeof(Transaction));
    if (!tx) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for deserialized transaction.");
        return NULL;
    }

    const uint8_t* ptr = data;
    size_t bytes_read = 0;

    // Read fixed fields
    if (bytes_read + sizeof(tx->type) > data_len) goto deserialize_error;
    memcpy(&tx->type, ptr, sizeof(tx->type));
    ptr += sizeof(tx->type);
    bytes_read += sizeof(tx->type);

    if (bytes_read + sizeof(tx->timestamp) > data_len) goto deserialize_error;
    memcpy(&tx->timestamp, ptr, sizeof(tx->timestamp));
    ptr += sizeof(tx->timestamp);
    bytes_read += sizeof(tx->timestamp);

    if (bytes_read + (SHA256_HEX_LEN + 1) > data_len) goto deserialize_error;
    memcpy(tx->sender_public_key_hash, ptr, SHA256_HEX_LEN + 1);
    ptr += (SHA256_HEX_LEN + 1);
    bytes_read += (SHA256_HEX_LEN + 1);

    if (bytes_read + (SHA256_HEX_LEN + 1) > data_len) goto deserialize_error;
    memcpy(tx->transaction_id, ptr, SHA256_HEX_LEN + 1);
    ptr += (SHA256_HEX_LEN + 1);
    bytes_read += (SHA256_HEX_LEN + 1);

    if (bytes_read + (SHA256_HEX_LEN * 2 + 1) > data_len) goto deserialize_error;
    memcpy(tx->signature, ptr, SHA256_HEX_LEN * 2 + 1);
    ptr += (SHA256_HEX_LEN * 2 + 1);
    bytes_read += (SHA256_HEX_LEN * 2 + 1);

    // Read payload based on type
    if (tx->type == TX_NEW_RECORD) {
        if (bytes_read + sizeof(tx->data.new_record.encrypted_data_len) > data_len) goto deserialize_error;
        memcpy(&tx->data.new_record.encrypted_data_len, ptr, sizeof(tx->data.new_record.encrypted_data_len));
        ptr += sizeof(tx->data.new_record.encrypted_data_len);
        bytes_read += sizeof(tx->data.new_record.encrypted_data_len);

        if (tx->data.new_record.encrypted_data_len > 0) {
            if (bytes_read + tx->data.new_record.encrypted_data_len > data_len) goto deserialize_error;
            tx->data.new_record.encrypted_data = (uint8_t*)malloc(tx->data.new_record.encrypted_data_len);
            if (!tx->data.new_record.encrypted_data) {
                logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for deserialized encrypted_data.");
                goto deserialize_error;
            }
            memcpy(tx->data.new_record.encrypted_data, ptr, tx->data.new_record.encrypted_data_len);
            ptr += tx->data.new_record.encrypted_data_len;
            bytes_read += tx->data.new_record.encrypted_data_len;
        } else {
            tx->data.new_record.encrypted_data = NULL; // Ensure it's NULL if length is 0
        }

        if (bytes_read + AES_GCM_IV_SIZE > data_len) goto deserialize_error;
        memcpy(tx->data.new_record.iv, ptr, AES_GCM_IV_SIZE);
        ptr += AES_GCM_IV_SIZE;
        bytes_read += AES_GCM_IV_SIZE;

        if (bytes_read + AES_GCM_TAG_SIZE > data_len) goto deserialize_error;
        memcpy(tx->data.new_record.tag, ptr, AES_GCM_TAG_SIZE);
        ptr += AES_GCM_TAG_SIZE;
        bytes_read += AES_GCM_TAG_SIZE;

        if (bytes_read + (SHA256_HEX_LEN + 1) > data_len) goto deserialize_error;
        memcpy(tx->data.new_record.original_record_hash, ptr, SHA256_HEX_LEN + 1);
        ptr += (SHA256_HEX_LEN + 1);
        bytes_read += (SHA256_HEX_LEN + 1);

    } else if (tx->type == TX_REQUEST_ACCESS || tx->type == TX_GRANT_ACCESS || tx->type == TX_REVOKE_ACCESS) {
        if (bytes_read + (SHA256_HEX_LEN + 1) > data_len) goto deserialize_error;
        memcpy(tx->data.access_control.related_record_hash, ptr, SHA256_HEX_LEN + 1);
        ptr += (SHA256_HEX_LEN + 1);
        bytes_read += (SHA256_HEX_LEN + 1);

        if (bytes_read + (SHA256_HEX_LEN + 1) > data_len) goto deserialize_error;
        memcpy(tx->data.access_control.target_user_public_key_hash, ptr, SHA256_HEX_LEN + 1);
        ptr += (SHA256_HEX_LEN + 1);
        bytes_read += (SHA256_HEX_LEN + 1);
    } else {
        logger_log(LOG_LEVEL_WARN, "Unknown transaction type (%d) during deserialization.", tx->type);
        // For unknown types, we might just assume no additional payload or handle specific errors.
        // For now, allow it to continue without reading more payload data.
    }

    if (bytes_read != data_len) {
        logger_log(LOG_LEVEL_WARN, "Deserialization warning: Mismatch in data length. Expected %zu, read %zu.", data_len, bytes_read);
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction deserialized successfully. Type: %s", get_transaction_type_string(tx->type));
    return tx;

deserialize_error:
    logger_log(LOG_LEVEL_ERROR, "Deserialization failed: Insufficient data or memory allocation error. Data len: %zu, Bytes read: %zu, Type: %d",
               data_len, bytes_read, tx ? tx->type : -1);
    transaction_destroy(tx); // Clean up any allocated memory
    return NULL;
}
