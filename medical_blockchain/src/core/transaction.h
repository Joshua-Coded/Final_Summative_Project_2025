#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <stddef.h> // For size_t
#include <stdbool.h>
#include "../crypto/hasher.h"       // For SHA256_HEX_LEN, SHA256_DIGEST_LENGTH (previously SHA256_HASH_SIZE)
#include "../medical/medical_record.h" // Make sure MedicalRecord struct is defined here
#include "../security/encryption.h" // For AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_256_KEY_SIZE

// Define TRANSACTION_ID_LEN based on SHA256_HEX_LEN
#ifndef TRANSACTION_ID_LEN
#define TRANSACTION_ID_LEN SHA256_HEX_LEN // Transaction ID will be its hash in HEX STRING format (64 chars)
#endif

/**
 * @brief Enumerates the types of transactions possible in the blockchain.
 */
typedef enum {
    TX_NEW_RECORD,          ///< A new medical record is being added.
    TX_REQUEST_ACCESS,      ///< A user is requesting access to a medical record.
    TX_GRANT_ACCESS,        ///< A data owner is granting access to a medical record.
    TX_REVOKE_ACCESS,       ///< A data owner is revoking access to a medical record.
    // Add other transaction types as needed
} TransactionType;

/**
 * @brief Represents a single transaction in the blockchain.
 * A transaction can be of various types, involving medical records or access control.
 */
typedef struct Transaction {
    TransactionType type;                   ///< The type of transaction (e.g., new record, access request).
    int64_t timestamp;                      ///< Time of transaction creation (Unix timestamp).
    char transaction_id[TRANSACTION_ID_LEN + 1];

    // Public key of the sender/initiator of the transaction (hex string)
    char sender_public_key_hash[SHA256_HEX_LEN + 1];

    // Signature of the transaction by the sender's private key
    char signature[SHA256_HEX_LEN * 2 + 1]; // Example: If ECDSA 64-byte signature, it's 128 hex chars.

    // Specific data for different transaction types
    union {
        // For TX_NEW_RECORD: contains the encrypted medical data
        struct {
            // Encrypted medical data (raw bytes)
            uint8_t* encrypted_data;
            size_t encrypted_data_len;
            uint8_t iv[AES_GCM_IV_SIZE];   // Initialization Vector for AES-GCM
            uint8_t tag[AES_GCM_TAG_SIZE]; // Authentication Tag for AES-GCM

            // Hash of the unencrypted medical record data (for integrity check, hex string)
            char original_record_hash[SHA256_HEX_LEN + 1];
        } new_record;

        // For TX_REQUEST_ACCESS, TX_GRANT_ACCESS, TX_REVOKE_ACCESS:
        // These transactions relate to an existing medical record.
        struct {
            char related_record_hash[SHA256_HEX_LEN + 1]; // Points to original record hash (hex string)
            char target_user_public_key_hash[SHA256_HEX_LEN + 1]; // Hash of user whose access is requested/granted/revoked
        } access_control;
    } data;
} Transaction;


// Function prototypes for transaction operations

/**
 * @brief Creates a new transaction.
 * @param type The type of transaction.
 * @param sender_public_key_hash Hex string of sender's public key hash.
 * @param signature Hex string of the transaction's signature.
 * @return A pointer to the newly created Transaction, or NULL on failure.
 */
Transaction* transaction_create(TransactionType type,
                                 const char sender_public_key_hash[SHA256_HEX_LEN + 1],
                                 const char signature[SHA256_HEX_LEN * 2 + 1]);

/**
 * @brief Adds new medical record data to a TX_NEW_RECORD transaction.
 * @param tx The transaction of type TX_NEW_RECORD.
 * @param encrypted_data The encrypted medical data (dynamically allocated). Marked const as this function copies it.
 * @param encrypted_data_len Length of the encrypted data.
 * @param iv The IV used for encryption.
 * @param tag The GCM tag generated during encryption.
 * @param original_record_hash The SHA256 hex hash of the original unencrypted data.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_new_record_data(Transaction* tx,
                                    const uint8_t* encrypted_data, size_t encrypted_data_len, // <<-- CHANGED: ADDED 'const'
                                    const uint8_t iv[AES_GCM_IV_SIZE],
                                    const uint8_t tag[AES_GCM_TAG_SIZE],
                                    const char original_record_hash[SHA256_HEX_LEN + 1]);

/**
 * @brief Sets data for access control transactions (TX_REQUEST_ACCESS, TX_GRANT_ACCESS, TX_REVOKE_ACCESS).
 * @param tx The transaction.
 * @param related_record_hash The hex hash of the medical record this transaction pertains to.
 * @param target_user_public_key_hash The hex hash of the public key of the user whose access is affected.
 * @return 0 on success, -1 on failure.
 */
int transaction_set_access_control_data(Transaction* tx,
                                        const char related_record_hash[SHA256_HEX_LEN + 1],
                                        const char target_user_public_key_hash[SHA256_HEX_LEN + 1]);

/**
 * @brief Calculates the hash of a transaction.
 * The transaction ID is the hash of its content.
 * @param tx A pointer to the transaction. Marked const as this function should not modify tx content.
 * @param output_hash A buffer to store the calculated hash (SHA256_DIGEST_LENGTH bytes).
 * @return 0 on success, -1 on failure.
 */
int transaction_calculate_hash(const Transaction* tx, uint8_t output_hash[SHA256_DIGEST_LENGTH]); // <<-- CHANGED: ADDED 'const'

/**
 * @brief Signs a transaction using a dummy mechanism.
 * In a real implementation, this would involve using the sender's private key
 * to sign the transaction's hash. This version only calculates the transaction ID
 * and populates a dummy signature.
 * @param tx A pointer to the transaction to sign.
 * @param private_key_hex A placeholder for the private key (not actually used for crypto here).
 * @return 0 on success, -1 on failure.
 */
int transaction_sign(Transaction* tx, const char* private_key_hex);

/**
 * @brief Verifies the signature of a transaction.
 * In a real implementation, this would involve using the sender's public key
 * to verify the transaction's hash against the provided signature.
 * @param tx A pointer to the transaction to verify.
 * @return true if the signature is valid, false otherwise.
 */
bool transaction_verify_signature(const Transaction* tx);

/**
 * @brief Verifies the integrity and validity of a transaction.
 * This might include verifying signatures, data consistency, etc.
 * @param tx A pointer to the transaction to verify.
 * @return 0 if the transaction is valid, -1 otherwise.
 */
int transaction_is_valid(const Transaction* tx);

/**
 * @brief Frees all memory allocated for a transaction.
 * @param tx A pointer to the transaction to destroy.
 */
void transaction_destroy(Transaction* tx);

/**
 * @brief Prints the details of a transaction to the console.
 * @param tx A pointer to the transaction to print.
 * @param encryption_key The key used for decryption if the transaction contains encrypted data (e.g., TX_NEW_RECORD).
 * Pass NULL if no decryption is needed or key is unavailable.
 */
void transaction_print(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]);

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
uint8_t* transaction_serialize(const Transaction* tx, size_t* size);

/**
 * @brief Placeholder for deserialization
 * This function is a minimal placeholder. Proper deserialization needs to
 * reconstruct the Transaction struct from a defined binary format,
 * handling variable-length data and union members correctly.
 * @param data A pointer to the serialized data.
 * @param size The size of the serialized data.
 * @return A pointer to the deserialized Transaction, or NULL on failure.
 */
Transaction* transaction_deserialize(const uint8_t* data, size_t size);


#endif // TRANSACTION_H
