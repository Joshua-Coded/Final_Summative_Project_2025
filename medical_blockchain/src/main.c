// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/blockchain.h"
#include "core/block.h"
#include "core/transaction.h" // Now uses encryption key
#include "utils/logger.h"
#include "mining/proof_of_work.h"
#include "storage/disk_storage.h"
#include "security/encryption.h" // Needed for key generation if not hardcoded

// External global variable from logger.c for setting log level
extern LogLevel current_log_level;

// !!! IMPORTANT: FOR DEMONSTRATION ONLY !!!
// In a real system, this key should be securely generated, stored, and managed.
// Never hardcode sensitive keys in production code.
static uint8_t g_encryption_key[AES_256_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x8a, 0xd2, 0x4c, 0x14, 0x57, 0x24, 0x56, 0x54,
    0x78, 0x8f, 0x15, 0x16, 0x2a, 0x9e, 0x4e, 0x12
}; // This is a common AES test key (256-bit)

int main() {
    // 1. Initialize Logger
    if (disk_storage_ensure_dir("data/logs") != 0) {
        fprintf(stderr, "Failed to create data/logs directory. Exiting.\n");
        return EXIT_FAILURE;
    }
    if (logger_init("data/logs/system.log") != 0) {
        fprintf(stderr, "Failed to initialize logger. Check data/logs directory permissions or existence.\n");
        return EXIT_FAILURE;
    }
    logger_log(LOG_LEVEL_INFO, "Starting Blockchain Medical Records System.");
    logger_set_level(LOG_LEVEL_INFO);

    printf("Welcome to the Blockchain Medical Records System!\n");

    // 2. Load or Create Blockchain
    Blockchain* medical_blockchain = NULL;
    const char* blockchain_file_path = DEFAULT_DATA_DIR "/" DEFAULT_BLOCKCHAIN_FILE;

    if (disk_storage_ensure_dir(DEFAULT_DATA_DIR) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create blockchain data directory: %s. Exiting.", DEFAULT_DATA_DIR);
        logger_shutdown();
        return EXIT_FAILURE;
    }

    medical_blockchain = disk_storage_load_blockchain(blockchain_file_path);

    if (medical_blockchain == NULL) {
        logger_log(LOG_LEVEL_INFO, "No existing blockchain found or failed to load. Creating new blockchain.");
        medical_blockchain = blockchain_create();
        if (medical_blockchain == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to create new blockchain. Exiting.");
            logger_shutdown();
            return EXIT_FAILURE;
        }
        logger_log(LOG_LEVEL_INFO, "New blockchain created successfully (Genesis Block).");
    } else {
        logger_log(LOG_LEVEL_INFO, "Blockchain loaded successfully (length: %zu).", medical_blockchain->length);
    }

    // --- Demonstrate adding a new block with transactions (only if the chain is fresh or short) ---
    Block* last_block = &medical_blockchain->chain[medical_blockchain->length - 1]; // Always get the current last block

    // Define some medical data
    const char* medical_data1 = "{ \"patient_id\": \"P001\", \"type\": \"diagnosis\", \"description\": \"Common cold\", \"doctor\": \"Dr. Smith\", \"date\": \"2023-01-15\" }";
    const char* medical_data2 = "{ \"patient_id\": \"P001\", \"type\": \"prescription\", \"medication\": \"Cough Syrup\", \"dosage\": \"10ml 3x daily\", \"doctor\": \"Dr. Smith\", \"date\": \"2023-01-16\" }";
    const char* medical_data3 = "{ \"patient_id\": \"P002\", \"type\": \"allergy_update\", \"allergy\": \"Penicillin\", \"severity\": \"High\", \"date\": \"2023-02-01\" }";

    // Only add new blocks if we just have the genesis block or if there's a command to add more
    if (medical_blockchain->length == 1) { // A very simple condition for adding a new block
        logger_log(LOG_LEVEL_INFO, "Adding a new block with sample encrypted transactions...");

        // Create transactions using the encryption key
        Transaction* tx1 = transaction_create("DoctorA_PubKey", "Patient1_PubKey", medical_data1, 10.0, g_encryption_key);
        Transaction* tx2 = transaction_create("Patient1_PubKey", "DoctorA_PubKey", medical_data2, 0.0, g_encryption_key);
        Transaction* tx3 = transaction_create("Hospital_PubKey", "Patient2_PubKey", medical_data3, 25.0, g_encryption_key);

        if (!tx1 || !tx2 || !tx3) {
            logger_log(LOG_LEVEL_ERROR, "Failed to create one or more transactions. Exiting block creation.");
            transaction_destroy(tx1); // Safe to call on NULL
            transaction_destroy(tx2);
            transaction_destroy(tx3);
            goto end_main; // Jump to cleanup
        }

        // Basic signing (placeholder)
        transaction_sign(tx1, "DoctorA_PrivateKey_For_Signing_Tx1");
        transaction_sign(tx2, "Patient1_PrivateKey_For_Signing_Tx2");
        transaction_sign(tx3, "Hospital_PrivateKey_For_Signing_Tx3");

        // Verify signatures (important before adding to a block)
        if (transaction_verify_signature(tx1, "DoctorA_PubKey") != 0) {
            logger_log(LOG_LEVEL_WARN, "Signature verification failed for Tx1! Potential tampering.");
        }
        if (transaction_verify_signature(tx2, "Patient1_PubKey") != 0) {
            logger_log(LOG_LEVEL_WARN, "Signature verification failed for Tx2!");
        }
        if (transaction_verify_signature(tx3, "Hospital_PubKey") != 0) {
            logger_log(LOG_LEVEL_WARN, "Signature verification failed for Tx3!");
        }


        // Create a new block (initially with nonce 0)
        Block* new_record_block = block_create(
            medical_blockchain->length, // Index of the new block
            last_block->hash,           // Hash of the previous block
            0                           // Initial nonce for mining
        );

        if (new_record_block != NULL) {
            // Add transactions to the new block
            block_add_transaction(new_record_block, tx1);
            block_add_transaction(new_record_block, tx2);
            block_add_transaction(new_record_block, tx3);

            // Mine the block
            logger_log(LOG_LEVEL_INFO, "Starting mining for block #%u...", new_record_block->index);
            if (proof_of_work_mine_block(new_record_block, DEFAULT_DIFFICULTY) == 0) {
                blockchain_add_block(medical_blockchain, new_record_block);
                logger_log(LOG_LEVEL_INFO, "Successfully mined and added new medical record block with encrypted transactions.");
            } else {
                logger_log(LOG_LEVEL_ERROR, "Failed to mine block #%u. Not adding to chain.", new_record_block->index);
                block_destroy(new_record_block);
            }

        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to create new record block.");
            // If block creation fails, transactions are not owned by the block, so free them.
            transaction_destroy(tx1); // Ensure these are still freed if block_create failed
            transaction_destroy(tx2);
            transaction_destroy(tx3);
        }
    } else {
        logger_log(LOG_LEVEL_INFO, "Blockchain already has %zu blocks. Not adding new sample block.", medical_blockchain->length);
    }


    // --- Validate the entire blockchain ---
    printf("\nValidating entire blockchain...\n");
    LogLevel original_log_level = current_log_level;
    logger_set_level(LOG_LEVEL_DEBUG);
    if (blockchain_is_valid(medical_blockchain) == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain is VALID and all blocks meet PoW criteria!");
    } else {
        logger_log(LOG_LEVEL_FATAL, "Blockchain is NOT VALID! Tampering detected or an issue occurred.");
    }
    logger_set_level(original_log_level);

    // --- Print all blocks in the blockchain ---
    printf("\n--- Current Blockchain State (Medical Data Decrypted) ---\n");
    for (size_t i = 0; i < medical_blockchain->length; i++) {
        block_print_with_decryption(&medical_blockchain->chain[i], g_encryption_key); // Use a new print function
        printf("--------------------------------\n");
    }

end_main:; // Label for goto

    // 3. Save Blockchain and Clean Up
    if (disk_storage_save_blockchain(medical_blockchain, blockchain_file_path) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to save blockchain to disk.");
    }

    blockchain_destroy(medical_blockchain);
    logger_log(LOG_LEVEL_INFO, "Blockchain destroyed.");
    logger_shutdown();

    printf("Exiting system.\n");
    return EXIT_SUCCESS;
}
