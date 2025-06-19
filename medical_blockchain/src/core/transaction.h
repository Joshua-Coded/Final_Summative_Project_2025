#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../crypto/hasher.h"
#include "../medical/medical_record.h"
#include "../security/encryption.h"
#include "../security/key_management.h" // Include for ECDSA_SIGNATURE_HEX_LEN

#ifndef TRANSACTION_ID_LEN
#define TRANSACTION_ID_LEN SHA256_HEX_LEN
#endif

// Define a reasonable max size for PEM keys
// 4096 is typically more than enough for ECDSA PEM strings
#define MAX_PEM_KEY_LEN 4096

typedef enum {
    TX_NEW_RECORD,
    TX_REQUEST_ACCESS,
    TX_GRANT_ACCESS,
    TX_REVOKE_ACCESS,
} TransactionType;

typedef struct Transaction {
    TransactionType type;
    int64_t timestamp;
    char transaction_id[TRANSACTION_ID_LEN + 1];
    char sender_public_key_hash[SHA256_HEX_LEN + 1];
    char signature[ECDSA_SIGNATURE_HEX_LEN + 1];

    // NEW: Add field for sender's full public key PEM string
    char sender_public_key_pem[MAX_PEM_KEY_LEN]; // Store the full PEM string here

    union {
        struct {
            uint8_t* encrypted_data;
            size_t encrypted_data_len;
            uint8_t iv[AES_GCM_IV_SIZE];
            uint8_t tag[AES_GCM_TAG_SIZE];
            char original_record_hash[SHA256_HEX_LEN + 1];
        } new_record;
        struct {
            char related_record_hash[SHA256_HEX_LEN + 1];
            char target_user_public_key_hash[SHA256_HEX_LEN + 1];
        } access_control;
    } data;
} Transaction;

// Creates a new transaction. Updated signature to include the public key PEM.
Transaction* transaction_create(TransactionType type,
                                const char sender_public_key_hash[SHA256_HEX_LEN + 1],
                                const char sender_public_key_pem[MAX_PEM_KEY_LEN]);

// Adds new medical record data to a TX_NEW_RECORD transaction.
int transaction_set_new_record_data(Transaction* tx,
                                    const uint8_t* encrypted_data, size_t encrypted_data_len,
                                    const uint8_t iv[AES_GCM_IV_SIZE],
                                    const uint8_t tag[AES_GCM_TAG_SIZE],
                                    const char original_record_hash[SHA256_HEX_LEN + 1]);

// Sets data for access control transactions.
int transaction_set_access_control_data(Transaction* tx,
                                        const char related_record_hash[SHA256_HEX_LEN + 1],
                                        const char target_user_public_key_hash[SHA256_HEX_LEN + 1]);

// Calculates the hash of a transaction (excluding its signature and ID).
int transaction_calculate_hash(const Transaction* tx, uint8_t output_hash[SHA256_DIGEST_LENGTH]);

// Signs a transaction using the provided private key PEM.
int transaction_sign(Transaction* tx, const char* private_key_pem);

// Verifies the signature of a transaction using its embedded public key PEM.
bool transaction_verify_signature(const Transaction* tx);

// Verifies the integrity and validity of a transaction.
int transaction_is_valid(const Transaction* tx);

// Frees all memory allocated for a transaction.
void transaction_destroy(Transaction* tx);

// Prints the details of a transaction to the console.
void transaction_print(const Transaction* tx, const uint8_t encryption_key[AES_256_KEY_SIZE]);

// Placeholder for serialization.
uint8_t* transaction_serialize(const Transaction* tx, size_t* size);

// Placeholder for deserialization.
Transaction* transaction_deserialize(const uint8_t* data, size_t size);

#endif // TRANSACTION_H
