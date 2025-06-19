#include "transaction.h"
#include "../crypto/hasher.h" // For hasher_sha256, hasher_bytes_to_hex, SHA256_DIGEST_LENGTH, SHA256_HEX_LEN
#include "../security/encryption.h" // For AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_256_KEY_SIZE
#include "../security/key_management.h" // Assuming this might contain public key retrieval (for verification)
// #include "../crypto/ecdsa.h" // Assuming your actual ECDSA sign/verify functions are here
#include "../utils/logger.h"
#include "../utils/colors.h" // For ANSI_COLOR_* macros
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/evp.h> // Explicitly include this to ensure full EVP_MD_CTX definition

// Placeholder for actual ECDSA signing/verification functions.
// YOU MUST IMPLEMENT THESE WITH OPENSSL'S ECDSA CAPABILITIES.
// These are examples of what their signatures might look like.
// For signature, it often returns a DER-encoded signature or similar, which then needs to be hex-encoded.
// For simplicity, let's assume it directly returns hex-encoded for now.
extern int ecdsa_sign_hash(const uint8_t* hash, size_t hash_len, const char* private_key_hex, char* signature_hex_output, size_t signature_hex_output_len);
extern bool ecdsa_verify_signature(const uint8_t* hash, size_t hash_len, const char* signature_hex, const char* public_key_hex);


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
 * @param type The transaction type.
 * @param sender_public_key_hash Hex string of sender's public key hash.
 * @param signature Hex string of the transaction's signature. (Placeholder, updated by transaction_sign)
 * @return A new Transaction, or NULL on failure.
 */
Transaction* transaction_create(TransactionType type,
                                const char sender_public_key_hash[SHA256_HEX_LEN + 1],
                                const char signature[SHA256_HEX_LEN * 2 + 1]) {
    if (sender_public_key_hash == NULL || signature == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input: sender_public_key_hash or signature is NULL.");
        return NULL;
    }

    Transaction* tx = (Transaction*)calloc(1, sizeof(Transaction));
    if (tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for transaction.");
        return NULL;
    }

    tx->type = type;
    tx->timestamp = time(NULL);

    strncpy(tx->sender_public_key_hash, sender_public_key_hash, SHA256_HEX_LEN);
    tx->sender_public_key_hash[SHA256_HEX_LEN] = '\0';

    strncpy(tx->signature, signature, SHA256_HEX_LEN * 2);
    tx->signature[SHA256_HEX_LEN * 2] = '\0';

    tx->transaction_id[0] = '\0';

    if (type == TX_NEW_RECORD) {
        tx->data.new_record.encrypted_data = NULL;
        tx->data.new_record.encrypted_data_len = 0;
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction created for type: %s", get_transaction_type_string(type));
    return tx;
}

/**
 * @brief Adds new medical record data to a TX_NEW_RECORD transaction.
 * @param tx The TX_NEW_RECORD transaction.
 * @param encrypted_data Encrypted medical data.
 * @param encrypted_data_len Length of encrypted data.
 * @param iv IV used for encryption.
 * @param tag GCM tag.
 * @param original_record_hash SHA256 hex hash of original unencrypted data.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_new_record_data(Transaction* tx,
                                    const uint8_t* encrypted_data, size_t encrypted_data_len,
                                    const uint8_t iv[AES_GCM_IV_SIZE],
                                    const uint8_t tag[AES_GCM_TAG_SIZE],
                                    const char original_record_hash[SHA256_HEX_LEN + 1]) {
    if (tx == NULL || tx->type != TX_NEW_RECORD || encrypted_data == NULL || original_record_hash == NULL ||
        encrypted_data_len == 0 || iv == NULL || tag == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input or transaction type mismatch for new record data.");
        return -1;
    }

    if (tx->data.new_record.encrypted_data != NULL) {
        free(tx->data.new_record.encrypted_data);
        tx->data.new_record.encrypted_data = NULL;
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

    logger_log(LOG_LEVEL_DEBUG, "New record data set. Encrypted data length: %zu", encrypted_data_len);
    return 0;
}

/**
 * @brief Sets data for access control transactions.
 * @param tx The transaction.
 * @param related_record_hash Hex hash of the medical record.
 * @param target_user_public_key_hash Hex hash of the target user's public key.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_access_control_data(Transaction* tx,
                                        const char related_record_hash[SHA256_HEX_LEN + 1],
                                        const char target_user_public_key_hash[SHA256_HEX_LEN + 1]) {
    if (tx == NULL || (tx->type != TX_REQUEST_ACCESS && tx->type != TX_GRANT_ACCESS && tx->type != TX_REVOKE_ACCESS) ||
        related_record_hash == NULL || target_user_public_key_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input or transaction type mismatch for access control data.");
        return -1;
    }

    strncpy(tx->data.access_control.related_record_hash, related_record_hash, SHA256_HEX_LEN);
    tx->data.access_control.related_record_hash[SHA256_HEX_LEN] = '\0';

    strncpy(tx->data.access_control.target_user_public_key_hash, target_user_public_key_hash, SHA256_HEX_LEN);
    tx->data.access_control.target_user_public_key_hash[SHA256_HEX_LEN] = '\0';

    logger_log(LOG_LEVEL_DEBUG, "Access control data set.");
    return 0;
}

/**
 * @brief Calculates the hash of a transaction (transaction ID).
 * @param tx The transaction.
 * @param output_hash Buffer for calculated hash (SHA256_DIGEST_LENGTH bytes).
 * @return 0 on success, -1 on failure.
 */
int transaction_calculate_hash(const Transaction* tx, uint8_t output_hash[SHA256_DIGEST_LENGTH]) {
    if (tx == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for hash calculation.");
        return -1;
    }

    EVP_MD_CTX *ctx = NULL;

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create EVP_MD_CTX for transaction hash.");
        return -1;
    }

    hasher_sha256_stream_init(ctx);

    char data_buffer[1024];

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

    switch (tx->type) {
        case TX_NEW_RECORD:
            hasher_sha256_stream_update(ctx, (const uint8_t*)tx->data.new_record.original_record_hash, strlen(tx->data.new_record.original_record_hash));
            snprintf(data_buffer, sizeof(data_buffer), "%zu", tx->data.new_record.encrypted_data_len);
            hasher_sha256_stream_update(ctx, (const uint8_t*)data_buffer, strlen(data_buffer));

            if (tx->data.new_record.encrypted_data != NULL && tx->data.new_record.encrypted_data_len > 0) {
                hasher_sha256_stream_update(ctx, tx->data.new_record.encrypted_data, tx->data.new_record.encrypted_data_len);
            } else {
                logger_log(LOG_LEVEL_WARN, "TX_NEW_RECORD has no encrypted data for hash calculation.");
            }
            hasher_sha256_stream_update(ctx, tx->data.new_record.iv, AES_GCM_IV_SIZE);
            hasher_sha256_stream_update(ctx, tx->data.new_record.tag, AES_GCM_TAG_SIZE);
            break;
        case TX_REQUEST_ACCESS:
        case TX_GRANT_ACCESS:
        case TX_REVOKE_ACCESS:
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
 * @brief Signs a transaction using the sender's private key.
 * @param tx The transaction to sign.
 * @param private_key_hex Sender's private key in hex.
 * @return 0 on success, -1 on failure.
 */
int transaction_sign(Transaction* tx, const char* private_key_hex) {
    if (tx == NULL || private_key_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for transaction_sign.");
        return -1;
    }

    uint8_t tx_data_hash_binary[SHA256_DIGEST_LENGTH];

    if (transaction_calculate_hash(tx, tx_data_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate transaction data hash for signing.");
        return -1;
    }

    char* tx_id_hex = hasher_bytes_to_hex(tx_data_hash_binary, SHA256_DIGEST_LENGTH);
    if (tx_id_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert transaction data hash to hex for ID.");
        return -1;
    }
    strncpy(tx->transaction_id, tx_id_hex, SHA256_HEX_LEN);
    tx->transaction_id[SHA256_HEX_LEN] = '\0';
    free(tx_id_hex);

    // --- ACTUAL CRYPTOGRAPHIC SIGNING ---
    // This is where OpenSSL's ECDSA signing function would be called.
    // ecdsa_sign_hash (or equivalent) should take the hash, private key,
    // and a buffer to store the resulting hex signature.
    if (ecdsa_sign_hash(tx_data_hash_binary, SHA256_DIGEST_LENGTH,
                        private_key_hex, tx->signature, sizeof(tx->signature)) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to cryptographically sign transaction hash.");
        return -1;
    }

    logger_log(LOG_LEVEL_INFO, "Transaction %s signed.", tx->transaction_id);
    return 0;
}

/**
 * @brief Verifies the signature of a transaction using the sender's public key.
 * @param tx The transaction to verify.
 * @return true if the signature is valid, false otherwise.
 */
bool transaction_verify_signature(const Transaction* tx) {
    if (tx == NULL || strlen(tx->transaction_id) == 0 || strlen(tx->signature) == 0 || strlen(tx->sender_public_key_hash) == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid transaction for signature verification: missing ID, signature, or sender key hash.");
        return false;
    }

    uint8_t recomputed_tx_data_hash_binary[SHA256_DIGEST_LENGTH];
    if (transaction_calculate_hash(tx, recomputed_tx_data_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to recalculate transaction data hash for signature verification.");
        return false;
    }

    char* recomputed_tx_id_hex = hasher_bytes_to_hex(recomputed_tx_data_hash_binary, SHA256_DIGEST_LENGTH);
    if (recomputed_tx_id_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert recomputed transaction data hash to hex for verification.");
        return false;
    }

    if (strcmp(tx->transaction_id, recomputed_tx_id_hex) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Transaction ID mismatch during signature verification. Stored ID: %s, Recomputed ID: %s",
                   tx->transaction_id, recomputed_tx_id_hex);
        free(recomputed_tx_id_hex);
        return false;
    }
    free(recomputed_tx_id_hex);

    // --- ACTUAL CRYPTOGRAPHIC SIGNATURE VERIFICATION ---
    // This is where OpenSSL's ECDSA verification function would be called.
    // ecdsa_verify_signature (or equivalent) should take the hash, the signature,
    // and the sender's public key hash (which is typically derived from the public key,
    // or the public key itself would be retrieved using this hash).
    bool is_valid = ecdsa_verify_signature(recomputed_tx_data_hash_binary, SHA256_DIGEST_LENGTH,
                                          tx->signature, tx->sender_public_key_hash);

    if (!is_valid) {
        logger_log(LOG_LEVEL_WARN, "Signature verification failed for transaction %s.", tx->transaction_id);
    } else {
        logger_log(LOG_LEVEL_DEBUG, "Signature verified successfully for transaction %s.", tx->transaction_id);
    }

    return is_valid;
}


/**
 * @brief Verifies the integrity and validity of a transaction.
 * @param tx The transaction to verify.
 * @return 0 if valid, -1 otherwise.
 */
int transaction_is_valid(const Transaction* tx) {
    if (tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot validate a NULL transaction.");
        return -1;
    }

    uint8_t recomputed_tx_hash_binary[SHA256_DIGEST_LENGTH];
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
        free(recomputed_tx_id_hex);
        return -1;
    }
    free(recomputed_tx_id_hex);

    if (!transaction_verify_signature(tx)) {
        logger_log(LOG_LEVEL_ERROR, "Transaction %s: Signature verification failed.", tx->transaction_id);
        return -1;
    }

    if (strlen(tx->sender_public_key_hash) == 0) {
        logger_log(LOG_LEVEL_WARN, "Transaction %s has empty sender public key hash.", tx->transaction_id);
        return -1;
    }

    switch (tx->type) {
        case TX_NEW_RECORD:
            if (tx->data.new_record.encrypted_data == NULL || tx->data.new_record.encrypted_data_len == 0 ||
                strlen(tx->data.new_record.original_record_hash) == 0) {
                logger_log(LOG_LEVEL_WARN, "TX_NEW_RECORD data incomplete for transaction %s.", tx->transaction_id);
                return -1;
            }
            break;
        case TX_REQUEST_ACCESS:
        case TX_GRANT_ACCESS:
        case TX_REVOKE_ACCESS:
            if (strlen(tx->data.access_control.related_record_hash) == 0 ||
                strlen(tx->data.access_control.target_user_public_key_hash) == 0) {
                logger_log(LOG_LEVEL_WARN, "Access control data incomplete for transaction %s.", tx->transaction_id);
                return -1;
            }
            break;
        default:
            logger_log(LOG_LEVEL_WARN, "Unknown transaction type (%d) during validation.", tx->type);
            break;
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction %s is valid.", tx->transaction_id);
    return 0;
}

/**
 * @brief Frees all memory for a transaction.
 * @param tx The transaction to destroy.
 */
void transaction_destroy(Transaction* tx) {
    if (tx == NULL) {
        return;
    }
    if (tx->type == TX_NEW_RECORD && tx->data.new_record.encrypted_data != NULL) {
        logger_log(LOG_LEVEL_DEBUG, "Freeing encrypted data for TX_NEW_RECORD.");
        free(tx->data.new_record.encrypted_data);
        tx->data.new_record.encrypted_data = NULL;
    }
    free(tx);
    logger_log(LOG_LEVEL_DEBUG, "Transaction structure destroyed.");
}


/**
 * @brief Prints transaction details.
 * @param tx The transaction to print.
 * @param encryption_key Key for decryption of TX_NEW_RECORD data (can be NULL).
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
    printf(ANSI_COLOR_BLUE "  Timestamp:                 " ANSI_COLOR_RESET "%ld (" ANSI_COLOR_BRIGHT_BLACK "%s" ANSI_COLOR_RESET ")", (long)tx->timestamp, ctime((const time_t*)&tx->timestamp));

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
                int decrypted_data_len = 0;

                decrypted_data_len = encryption_decrypt_aes_gcm(
                    tx->data.new_record.encrypted_data,
                    (int)tx->data.new_record.encrypted_data_len,
                    encryption_key,
                    tx->data.new_record.iv,
                    tx->data.new_record.tag,
                    &decrypted_data
                );

                if (decrypted_data_len > 0 && decrypted_data != NULL) {
                    printf(ANSI_COLOR_GREEN "    Decrypted Data: %.*s\n" ANSI_COLOR_RESET,
                           decrypted_data_len, (char*)decrypted_data);
                    free(decrypted_data);
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
 * @param tx The Transaction.
 * @param size Pointer to store the size of serialized data.
 * @return Serialized data, or NULL on failure.
 */
uint8_t* transaction_serialize(const Transaction* tx, size_t* size) {
    if (!tx) {
        *size = 0;
        return NULL;
    }

    size_t base_size = sizeof(tx->type) + sizeof(tx->timestamp) +
                       (SHA256_HEX_LEN + 1) + (SHA256_HEX_LEN + 1) + (SHA256_HEX_LEN * 2 + 1);

    size_t payload_size = 0;
    size_t encrypted_data_actual_len = 0;

    if (tx->type == TX_NEW_RECORD) {
        payload_size += sizeof(tx->data.new_record.encrypted_data_len);
        payload_size += AES_GCM_IV_SIZE;
        payload_size += AES_GCM_TAG_SIZE;
        payload_size += (SHA256_HEX_LEN + 1);
        if (tx->data.new_record.encrypted_data != NULL) {
            encrypted_data_actual_len = tx->data.new_record.encrypted_data_len;
            payload_size += encrypted_data_actual_len;
        }
    } else if (tx->type == TX_REQUEST_ACCESS || tx->type == TX_GRANT_ACCESS || tx->type == TX_REVOKE_ACCESS) {
        payload_size += (SHA256_HEX_LEN + 1);
        payload_size += (SHA256_HEX_LEN + 1);
    }

    *size = base_size + payload_size;
    uint8_t* buffer = (uint8_t*)malloc(*size);
    if (!buffer) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for serialization buffer.");
        *size = 0;
        return NULL;
    }

    uint8_t* ptr = buffer;

    memcpy(ptr, &tx->type, sizeof(tx->type));
    ptr += sizeof(tx->type);
    memcpy(ptr, &tx->timestamp, sizeof(tx->timestamp));
    ptr += sizeof(tx->timestamp);
    memcpy(ptr, tx->sender_public_key_hash, SHA256_HEX_LEN + 1);
    ptr += (SHA256_HEX_LEN + 1);
    memcpy(ptr, tx->transaction_id, SHA256_HEX_LEN + 1);
    ptr += (SHA256_HEX_LEN + 1);
    memcpy(ptr, tx->signature, SHA256_HEX_LEN * 2 + 1);
    ptr += (SHA256_HEX_LEN * 2 + 1);

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
 * @brief Deserializes a byte array into a Transaction.
 * @param data Serialized transaction data.
 * @param data_len Length of data.
 * @return Deserialized Transaction, or NULL on failure.
 */
Transaction* transaction_deserialize(const uint8_t* data, size_t data_len) {
    if (!data || data_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for transaction_deserialize.");
        return NULL;
    }

    Transaction* tx = (Transaction*)calloc(1, sizeof(Transaction));
    if (!tx) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for deserialized transaction.");
        return NULL;
    }

    const uint8_t* ptr = data;
    size_t bytes_read = 0;

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

    if (tx->type == TX_NEW_RECORD) {
        if (bytes_read + sizeof(tx->data.new_record.encrypted_data_len) > data_len) goto deserialize_error;
        memcpy(&tx->data.new_record.encrypted_data_len, ptr, sizeof(tx->data.new_record.encrypted_data_len));
        ptr += sizeof(tx->data.new_record.encrypted_data_len);
        bytes_read += sizeof(tx->data.new_record.encrypted_data_len);

        if (tx->data.new_record.encrypted_data_len > 0) {
            if (bytes_read + tx->data.new_record.encrypted_data_len > data_len) goto deserialize_error;
            tx->data.new_record.encrypted_data = (uint8_t*)malloc(tx->data.new_record.encrypted_data_len);
            if (!tx->data.new_record.encrypted_data) {
                logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for encrypted_data during deserialization.");
                goto deserialize_error;
            }
            memcpy(tx->data.new_record.encrypted_data, ptr, tx->data.new_record.encrypted_data_len);
            ptr += tx->data.new_record.encrypted_data_len;
            bytes_read += tx->data.new_record.encrypted_data_len;
        } else {
            tx->data.new_record.encrypted_data = NULL;
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
    }

    if (bytes_read != data_len) {
        logger_log(LOG_LEVEL_WARN, "Deserialization warning: Mismatch in data length. Expected %zu, read %zu.", data_len, bytes_read);
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction deserialized successfully. Type: %s", get_transaction_type_string(tx->type));
    return tx;

deserialize_error:
    logger_log(LOG_LEVEL_ERROR, "Deserialization failed. Data len: %zu, Bytes read: %zu, Type: %d",
               data_len, bytes_read, tx ? tx->type : -1);
    transaction_destroy(tx);
    return NULL;
}
