// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/blockchain.h"
#include "core/block.h"
#include "core/transaction.h"
#include "utils/logger.h"
#include "mining/proof_of_work.h"

// External global variable from logger.c for setting log level
extern LogLevel current_log_level;

int main() {
    // Initialize logger
    // Ensure the data/logs directory exists. If not, the fopen in logger_init will fail.
    // You might want to add a Makefile rule or runtime check for this.
    if (logger_init("data/logs/system.log") != 0) {
        fprintf(stderr, "Failed to initialize logger. Check data/logs directory permissions or existence.\n");
        return EXIT_FAILURE;
    }
    logger_log(LOG_LEVEL_INFO, "Starting Blockchain Medical Records System.");
    logger_set_level(LOG_LEVEL_INFO); // Set default log level for console output (e.g., INFO and above)

    printf("Welcome to the Blockchain Medical Records System!\n");

    Blockchain* medical_blockchain = blockchain_create();
    if (medical_blockchain == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create blockchain. Exiting.");
        logger_shutdown();
        return EXIT_FAILURE;
    }
    logger_log(LOG_LEVEL_INFO, "Blockchain created successfully (Genesis Block).");

    // --- Demonstrate adding a new block with transactions ---

    // Create and add some transactions for the next block
    Transaction* tx1 = transaction_create("DoctorA_PubKey", "Patient1_PubKey",
                                         "{ \"record_id\": \"REC001\", \"type\": \"diagnosis\", \"value\": \"Flu\", \"date\": \"2023-01-15\" }", 10);
    Transaction* tx2 = transaction_create("Patient1_PubKey", "DoctorA_PubKey",
                                         "{ \"record_id\": \"REC001\", \"type\": \"consent\", \"value\": \"Granted\", \"date\": \"2023-01-16\" }", 0);
    Transaction* tx3 = transaction_create("Hospital_PubKey", "Patient2_PubKey",
                                         "{ \"record_id\": \"REC002\", \"type\": \"prescription\", \"med\": \"Amoxicillin\", \"date\": \"2023-02-01\" }", 25);

    // Basic signing (placeholder; actual signing would be more complex)
    // In a real system, verification would use the public key associated with sender_id.
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


    // Get the last block's hash to link the new block
    Block* last_block = &medical_blockchain->chain[medical_blockchain->length - 1];

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

        // Mine the block (find nonce that satisfies Proof of Work difficulty)
        logger_log(LOG_LEVEL_INFO, "Starting mining for block #%u...", new_record_block->index);
        // Using DEFAULT_DIFFICULTY from mining/proof_of_work.h
        if (proof_of_work_mine_block(new_record_block, DEFAULT_DIFFICULTY) == 0) {
            // Add the successfully mined block to the blockchain
            blockchain_add_block(medical_blockchain, new_record_block);
            logger_log(LOG_LEVEL_INFO, "Successfully mined and added new medical record block with transactions.");
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to mine block #%u. Not adding to chain.", new_record_block->index);
            // If mining fails, we must destroy the block and its transactions manually
            block_destroy(new_record_block);
            // Note: If transactions were successfully added to the block, block_destroy frees them.
            // If block_create failed, then tx1, tx2, tx3 would need to be freed here.
        }

    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new record block.");
        // If block creation fails, transactions are not owned by the block, so free them.
        transaction_destroy(tx1);
        transaction_destroy(tx2);
        transaction_destroy(tx3);
    }

    // --- Validate the entire blockchain ---
    printf("\nValidating entire blockchain...\n");
    // Temporarily increase log level to see detailed validation messages
    LogLevel original_log_level = current_log_level;
    logger_set_level(LOG_LEVEL_DEBUG); // Set to DEBUG to see more validation steps
    if (blockchain_is_valid(medical_blockchain) == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain is VALID and all blocks meet PoW criteria!");
    } else {
        logger_log(LOG_LEVEL_FATAL, "Blockchain is NOT VALID! Tampering detected or an issue occurred.");
    }
    logger_set_level(original_log_level); // Restore previous log level

    // --- Print all blocks in the blockchain ---
    printf("\n--- Current Blockchain State ---\n");
    for (size_t i = 0; i < medical_blockchain->length; i++) {
        block_print(&medical_blockchain->chain[i]);
        printf("--------------------------------\n");
    }

    // --- Clean up and exit ---
    blockchain_destroy(medical_blockchain); // This also destroys all blocks and their transactions
    logger_log(LOG_LEVEL_INFO, "Blockchain destroyed.");
    logger_shutdown(); // Close the log file

    printf("Exiting system.\n");
    return EXIT_SUCCESS;
}
