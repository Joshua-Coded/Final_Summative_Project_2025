// src/core/block.c
#include "block.h"
#include "../crypto/hasher.h" // For SHA256_HEX_LEN and hashing functions
#include "../utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Creates a new block.
 * @param index The index of the block in the blockchain.
 * @param prev_hash The hash of the previous block.
 * @param nonce The nonce for the Proof-of-Work.
 * @return A pointer to the newly created Block on success, NULL on failure.
 * The caller is responsible for freeing the block using block_destroy.
 */
Block* block_create(unsigned int index, const char* prev_hash, unsigned int nonce) {
    if (prev_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for block_create: prev_hash is NULL.");
        return NULL;
    }

    Block* block = (Block*)malloc(sizeof(Block));
    if (block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for new block.");
        return NULL;
    }

    block->index = index;
    block->timestamp = time(NULL);
    strncpy(block->prev_hash, prev_hash, SHA256_HEX_LEN);
    block->prev_hash[SHA256_HEX_LEN] = '\0'; // Ensure null termination
    block->nonce = nonce;
    block->transactions = NULL;
    block->num_transactions = 0;

    // Calculate initial hash (will be re-calculated during mining)
    if (block_calculate_hash(block, block->hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate initial hash for block #%u.", block->index);
        block_destroy(block);
        return NULL;
    }

    logger_log(LOG_LEVEL_DEBUG, "Block #%u created with prev_hash: %s", block->index, block->prev_hash);
    return block;
}

/**
 * @brief Destroys a block and frees all its allocated memory, including transactions.
 * @param block A pointer to the Block to destroy.
 */
void block_destroy(Block* block) {
    if (block == NULL) {
        return;
    }

    // Free each transaction
    if (block->transactions != NULL) {
        for (size_t i = 0; i < block->num_transactions; i++) {
            if (block->transactions[i] != NULL) {
                transaction_destroy(block->transactions[i]); // Use transaction_destroy to free its internal memory
            }
        }
        free(block->transactions); // Free the array of pointers
        block->transactions = NULL;
    }

    free(block);
    logger_log(LOG_LEVEL_DEBUG, "Block destroyed.");
}

/**
 * @brief Adds a transaction to a block.
 * @param block A pointer to the Block to which the transaction will be added.
 * @param transaction A pointer to the Transaction to add.
 * @return 0 on success, -1 on failure.
 */
int block_add_transaction(Block* block, Transaction* transaction) {
    if (block == NULL || transaction == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for block_add_transaction.");
        return -1;
    }

    // Reallocate memory for the transactions array
    Transaction** new_transactions = (Transaction**)realloc(block->transactions, (block->num_transactions + 1) * sizeof(Transaction*));
    if (new_transactions == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to reallocate memory for transactions in Block #%u.", block->index);
        return -1;
    }

    block->transactions = new_transactions;
    block->transactions[block->num_transactions] = transaction; // Add the new transaction
    block->num_transactions++;

    logger_log(LOG_LEVEL_DEBUG, "Transaction %s added to Block #%u. Total transactions: %zu",
               transaction->transaction_id, block->index, block->num_transactions);
    return 0;
}

/**
 * @brief Calculates the SHA256 hash of a block.
 * The hash includes all block metadata and a "simplified merkle root" of transactions.
 * For simplicity, we concatenate all transaction hashes. A real Merkle tree is more complex.
 * @param block A pointer to the Block.
 * @param output_hash A buffer to store the resulting SHA256 hash (SHA256_HEX_LEN + 1 bytes).
 * @return 0 on success, -1 on failure.
 */
int block_calculate_hash(const Block* block, char* output_hash) {
    if (block == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for block_calculate_hash.");
        return -1;
    }

    // Merkle root placeholder: concatenate all transaction hashes
    // For a real system, a Merkle tree would be constructed.
    char transactions_hash_concat[MAX_TRANSACTIONS_PER_BLOCK * (SHA256_HEX_LEN + 1) + 1];
    transactions_hash_concat[0] = '\0'; // Initialize empty string

    for (size_t i = 0; i < block->num_transactions; i++) {
        if (block->transactions[i] == NULL) {
            logger_log(LOG_LEVEL_ERROR, "NULL transaction found in block #%u during hash calculation.", block->index);
            return -1;
        }
        char tx_hash[SHA256_HEX_LEN + 1];
        if (transaction_calculate_hash(block->transactions[i], tx_hash) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for transaction %zu in block #%u.", i, block->index);
            return -1;
        }
        strncat(transactions_hash_concat, tx_hash, sizeof(transactions_hash_concat) - strlen(transactions_hash_concat) - 1);
    }

    // Combine all block data into a single string for hashing
    // Index + Timestamp + Prev Hash + Nonce + Merkle Root (simplified)
    size_t buffer_len = 256 + strlen(transactions_hash_concat); // Ample buffer
    char* data_to_hash = (char*)malloc(buffer_len);
    if (data_to_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for block hashing.");
        return -1;
    }

    snprintf(data_to_hash, buffer_len, "%u%ld%s%u%s",
             block->index, (long)block->timestamp, block->prev_hash,
             block->nonce, transactions_hash_concat);

    if (hasher_sha256((const uint8_t*)data_to_hash, strlen(data_to_hash), output_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "SHA256 hashing failed for block.");
        free(data_to_hash);
        return -1;
    }

    free(data_to_hash);
    return 0;
}

/**
 * @brief Prints the details of a block. (Original, doesn't handle decryption)
 * @param block A pointer to the Block to print.
 */
void block_print(const Block* block) {
    // This function will now default to not decrypting, for backward compatibility
    // or if a key is not explicitly provided.
    block_print_with_decryption(block, NULL);
}

/**
 * @brief Prints the details of a block, attempting to decrypt medical data.
 * @param block A pointer to the Block to print.
 * @param encryption_key The AES encryption key (32 bytes for AES-256) for decrypting medical data, or NULL if not available.
 */
void block_print_with_decryption(const Block* block, const uint8_t encryption_key[AES_256_KEY_SIZE]) {
    if (block == NULL) {
        printf("NULL Block\n");
        return;
    }
    printf("Block #%u\n", block->index);
    printf("  Timestamp: %ld (%s)", (long)block->timestamp, ctime(&block->timestamp)); // ctime adds newline
    printf("  Previous Hash: %s\n", block->prev_hash);
    printf("  Hash: %s\n", block->hash);
    printf("  Nonce: %u\n", block->nonce);
    printf("  Transactions (%zu):\n", block->num_transactions);
    for (size_t i = 0; i < block->num_transactions; i++) {
        printf("    Transaction %zu:\n", i + 1);
        transaction_print(block->transactions[i], encryption_key); // Pass the key to transaction_print
    }
}
