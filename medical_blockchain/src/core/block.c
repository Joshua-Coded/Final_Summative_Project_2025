// src/core/block.c
#include "core/block.h" // Include block.h first
#include "crypto/hasher.h" // For SHA256_HEX_LEN and hashing functions
#include "utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Creates a new block.
 * @param index The index of the block in the blockchain.
 * @param prev_hash The hash of the previous block.
 * @param nonce The nonce for the Proof-of-Work.
 * @param transactions An array of transactions to include in the block.
 * @param num_transactions The number of transactions in the array.
 * @return A pointer to the newly created Block on success, NULL on failure.
 * The caller is responsible for freeing the block using block_destroy.
 */
Block* block_create(unsigned int index, const char* prev_hash, unsigned int nonce,
                    Transaction* transactions, unsigned int num_transactions) {
    if (prev_hash == NULL || (transactions == NULL && num_transactions > 0)) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for block_create: prev_hash is NULL or transactions/count mismatch.");
        return NULL;
    }

    Block* block = (Block*)malloc(sizeof(Block));
    if (block == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to allocate memory for Block.");
        return NULL;
    }

    block->index = index;
    strncpy(block->prev_hash, prev_hash, SHA256_HEX_LEN);
    block->prev_hash[SHA256_HEX_LEN] = '\0'; // Ensure null termination
    block->timestamp = time(NULL);
    block->nonce = nonce;
    block->num_transactions = 0; // Initialize to 0, add them using block_add_transaction

    // Copy transactions into the block
    for (unsigned int i = 0; i < num_transactions; i++) {
        if (block_add_transaction(block, &transactions[i]) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to add transaction to block %u.", block->index);
            block_destroy(block);
            return NULL;
        }
    }

    // Hash is calculated after all data is set
    block_calculate_hash(block);

    logger_log(LOG_LEVEL_DEBUG, "Block %u created.", block->index);
    return block;
}

/**
 * @brief Frees the memory allocated for a block.
 * @param block A pointer to the Block to be destroyed.
 */
void block_destroy(Block* block) {
    if (block != NULL) {
        // No explicit freeing of transactions needed if they are part of the struct array
        free(block);
        logger_log(LOG_LEVEL_DEBUG, "Block destroyed.");
    }
}

/**
 * @brief Calculates the SHA256 hash of a block.
 * The hash is based on index, previous hash, timestamp, nonce, and all transaction data.
 * @param block A pointer to the Block for which to calculate the hash.
 */
void block_calculate_hash(Block* block) {
    char data_to_hash[1024]; // Adjust size as necessary for all block data + transactions
    int offset = 0;

    // Format basic block data
    offset += snprintf(data_to_hash + offset, sizeof(data_to_hash) - offset,
                       "%u%s%ld%u", block->index, block->prev_hash, block->timestamp, block->nonce);

    // Add transaction data to the hash input
    for (unsigned int i = 0; i < block->num_transactions; i++) {
        offset += snprintf(data_to_hash + offset, sizeof(data_to_hash) - offset,
                           "%s%s%f%ld", block->transactions[i].sender,
                           block->transactions[i].recipient,
                           block->transactions[i].amount,
                           block->transactions[i].timestamp);
        // You might also include signature and transaction hash if they are part of the hashing for validity
        // offset += snprintf(data_to_hash + offset, sizeof(data_to_hash) - offset, "%s%s",
        //                    block->transactions[i].signature, block->transactions[i].hash);
    }

    char* new_hash = sha256_hash(data_to_hash); // Assuming sha256_hash returns malloc'd string
    if (new_hash == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to calculate hash for block %u.", block->index);
        exit(EXIT_FAILURE); // Critical error, terminate
    }
    strncpy(block->hash, new_hash, SHA256_HEX_LEN);
    block->hash[SHA256_HEX_LEN] = '\0';
    free(new_hash); // Free the malloc'd hash string

    logger_log(LOG_LEVEL_DEBUG, "Block %u hash calculated: %s", block->index, block->hash);
}

/**
 * @brief Prints the details of a block.
 * @param block A pointer to the Block to be printed.
 */
void block_print(const Block* block) {
    if (block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Attempted to print a NULL block.");
        return;
    }
    printf("--- Block #%u ---\n", block->index);
    printf("Hash: %s\n", block->hash);
    printf("Prev Hash: %s\n", block->prev_hash);
    printf("Timestamp: %ld\n", block->timestamp);
    printf("Nonce: %u\n", block->nonce);
    printf("Transactions (%u):\n", block->num_transactions);
    for (unsigned int i = 0; i < block->num_transactions; i++) {
        transaction_print(&block->transactions[i]); // Assuming transaction_print exists
    }
    printf("-----------------\n");
}

/**
 * @brief Adds a transaction to a block.
 * @param block A pointer to the Block to add the transaction to.
 * @param transaction A pointer to the Transaction to be added.
 * @return 0 on success, -1 if the block is full.
 */
int block_add_transaction(Block* block, const Transaction* transaction) {
    if (block->num_transactions >= MAX_TRANSACTIONS_PER_BLOCK) {
        logger_log(LOG_LEVEL_WARN, "Block %u is full, cannot add more transactions.", block->index);
        return -1;
    }
    // Deep copy the transaction
    block->transactions[block->num_transactions] = *transaction; // Structure copy
    block->num_transactions++;
    logger_log(LOG_LEVEL_DEBUG, "Transaction added to block %u.", block->index);
    return 0;
}
