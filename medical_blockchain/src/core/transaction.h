// src/core/transaction.h
#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stddef.h> // For size_t
#include <stdint.h> // For uint8_t
#include <time.h>   // For time_t
#include "config/blockchain_config.h" // For MAX_ID_LENGTH, etc.
#include "security/encryption.h" // Include for AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE

// The actual hash size (SHA256_HEX_LEN) is typically defined in crypto/hasher.h
// or a shared config. Assuming SHA256_HEX_LEN is accessible via blockchain_config.h
#define MAX_TRANSACTION_ID_LENGTH SHA256_HEX_LEN

// --- Transaction Structure ---
typedef struct Transaction {
    char transaction_id[MAX_TRANSACTION_ID_LENGTH + 1]; // Unique hash of transaction data
    char sender_id[MAX_ID_LENGTH + 1];                  // Public key / identifier of sender
    char recipient_id[MAX_ID_LENGTH + 1];              // Public key / identifier of recipient

    uint8_t* encrypted_medical_data;                    // Dynamically allocated encrypted data (ciphertext)
    int encrypted_medical_data_len;                     // Length of the encrypted data

    uint8_t iv[AES_GCM_IV_SIZE];                       // Initialization Vector for AES-GCM
    uint8_t tag[AES_GCM_TAG_SIZE];                     // Authentication Tag for AES-GCM

    char signature[MAX_SIGNATURE_LENGTH + 1];          // Digital signature of the transaction content
    time_t timestamp;                                   // Time of transaction creation
    double value;                                       // Arbitrary value/fee for transaction (e.g., associated cost, or 0)
} Transaction;

/**
 * @brief Creates a new transaction.
 *
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
                                const uint8_t encryption_key[AES_256_KEY_SIZE]);

/**
 * @brief Destroys a transaction and frees its allocated memory.
 * @param tx A pointer to the Transaction to destroy.
 */
void transaction_destroy(Transaction* tx);

/**
 * @brief Signs a transaction. (Placeholder - actual cryptographic signing needed)
 * @param tx A pointer to the Transaction to sign.
 * @param private_key A placeholder for the private key.
 * @return 0 on success, -1 on failure.
 */
int transaction_sign(Transaction* tx, const char* private_key);

/**
 * @brief Verifies the signature of a transaction. (Placeholder - actual cryptographic verification needed)
 * @param tx A pointer to the Transaction to verify.
 * @param public_key A placeholder for the public key.
 * @return 0 on success (signature valid), -1 on failure (signature invalid).
 */
int transaction_verify_signature(const Transaction* tx, const char* public_key);

/**
 * @brief Prints the details of a transaction.
 * @param tx A pointer to the Transaction to print.
 * @param encryption_key The AES encryption key (32 bytes for AES-256) needed for decryption, or NULL if not decrypting.
 */
void transaction_print(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]);

/**
 * @brief Calculates the hash of a transaction.
 * This is crucial for verifying transaction integrity and including in blocks.
 * @param tx A pointer to the Transaction.
 * @param output_hash A buffer to store the resulting SHA256 hash (SHA256_HEX_LEN + 1 bytes).
 * @return 0 on success, -1 on failure.
 */
int transaction_calculate_hash(const Transaction* tx, char* output_hash);

/**
 * @brief Decrypts the medical data of a transaction.
 * @param tx The transaction containing the encrypted medical data.
 * @param encryption_key The AES encryption key (32 bytes for AES-256).
 * @return A dynamically allocated string containing the decrypted plaintext on success, NULL on failure.
 * The caller is responsible for freeing this string.
 */
char* transaction_decrypt_medical_data(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]);

#endif // TRANSACTION_H
