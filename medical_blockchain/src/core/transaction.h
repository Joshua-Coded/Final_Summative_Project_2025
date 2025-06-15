// src/core/transaction.h
#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h> // For uint8_t, uint32_t
#include <stddef.h> // For size_t
#include "../config/config.h" // Include config.h for MAX_ID_LENGTH and other common defines
#include <time.h>
// Assuming these are defined in a central config or security header
// #define MAX_ID_LENGTH 36 // E.g., for UUIDs or public key identifiers <-- This line should be REMOVED if it exists.
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define SHA256_HASH_SIZE 32 // Assuming BLOCK_HASH_SIZE also refers to SHA256 output

typedef struct Transaction {
    // Basic transaction data
    // Use fixed-size arrays for IDs if they have a known max length (e.g., hash of public key)
    char sender_id[MAX_ID_LENGTH + 1]; // This now uses the definition from config.h
    char recipient_id[MAX_ID_LENGTH + 1]; // This now uses the definition from config.h
    time_t timestamp;
    double value;

    // Encrypted Medical Data (binary blob)
    uint8_t* encrypted_medical_data;
    size_t encrypted_medical_data_len;
    uint8_t iv[AES_GCM_IV_SIZE]; // Initialization Vector
    uint8_t tag[AES_GCM_TAG_SIZE]; // Authentication Tag

    // Transaction ID (hash of transaction data, binary)
    uint8_t transaction_id[SHA256_HASH_SIZE];

    // Transaction Signature (binary)
    uint8_t signature[SHA256_HASH_SIZE]; // Placeholder for actual cryptographic signature bytes

} Transaction;

// Function prototypes
int transaction_calculate_hash(const Transaction* tx, uint8_t* output_hash);

Transaction* transaction_create(const char* sender_id, const char* recipient_id,
                                 const char* medical_data, double value,
                                 const uint8_t encryption_key[AES_256_KEY_SIZE]);
void transaction_destroy(Transaction* tx);
int transaction_sign(Transaction* tx, const char* private_key);
int transaction_verify_signature(const Transaction* tx, const char* public_key);
char* transaction_decrypt_medical_data(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]);
void transaction_print(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]);

// --- ADD THIS LINE ---
int transaction_is_valid(const Transaction* tx);

#endif // TRANSACTION_H
