// src/core/blockchain.c
#include "core/blockchain.h"
#include "core/block.h"      // For block-related functions/definitions
#include "core/transaction.h"  // For transaction_destroy, transaction_is_valid
#include "utils/logger.h"    // For logging (changed from ../utils/logger.h)
#include "utils/colors.h"    // Include colors header
#include "crypto/hasher.h"   // For BLOCK_HASH_SIZE, hasher_bytes_to_hex (changed from ../crypto/hasher.h)
#include "mining/proof_of_work.h" // For proof_of_work_mine (changed from ../mining/proof_of_work.h)
#include "config/config.h"   // For DEFAULT_DIFFICULTY and PENDING_TRANSACTIONS_INITIAL_CAPACITY (changed from ../config/config.h)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Initial capacity for the blockchain array of Block* pointers
#define CHAIN_INITIAL_CAPACITY 10

// Define the previous hash for the genesis block (all zeros in binary)
static const uint8_t GENESIS_PREV_HASH_BYTES[BLOCK_HASH_SIZE] = {0}; // All 32 bytes are initialized to 0

/**
 * @brief Initializes a new blockchain.
 * @return A pointer to the newly created Blockchain structure, or NULL on failure.
 */
Blockchain* blockchain_create() {
    Blockchain* bc = (Blockchain*)malloc(sizeof(Blockchain));
    if (bc == NULL) {
        print_red("Failed to allocate memory for Blockchain\n"); // Using helper
        return NULL;
    }

    // Initialize chain members
    bc->chain = (Block**)malloc(sizeof(Block*) * CHAIN_INITIAL_CAPACITY);
    if (bc->chain == NULL) {
        print_red("Failed to allocate memory for blockchain chain (array of Block pointers)\n"); // Using helper
        free(bc);
        return NULL;
    }
    bc->capacity = CHAIN_INITIAL_CAPACITY;
    bc->length = 0;
    bc->difficulty = DEFAULT_DIFFICULTY; // Initialize difficulty

    // Initialize pending_transactions members
    bc->pending_transactions = (Transaction**)malloc(sizeof(Transaction*) * PENDING_TRANSACTIONS_INITIAL_CAPACITY);
    if (bc->pending_transactions == NULL) {
        print_red("Failed to allocate memory for pending transactions\n"); // Using helper
        free(bc->chain);
        free(bc);
        return NULL;
    }
    bc->pending_transactions_capacity = PENDING_TRANSACTIONS_INITIAL_CAPACITY;
    bc->num_pending_transactions = 0;

    // Create the genesis block
    Block* genesis_block = block_create(0, GENESIS_PREV_HASH_BYTES);
    if (genesis_block == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create genesis block.");
        free(bc->pending_transactions); // Free new member too
        free(bc->chain);
        free(bc);
        return NULL;
    }

    // Mine the genesis block
    logger_log(LOG_LEVEL_INFO, "Mining Genesis Block (Block #0) with difficulty %d...", DEFAULT_DIFFICULTY);
    if (block_mine(genesis_block, DEFAULT_DIFFICULTY) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to mine genesis block.");
        block_destroy(genesis_block);
        free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        return NULL;
    }

    // Add genesis block to the chain.
    if (blockchain_add_block(bc, genesis_block) != 0) {
        block_destroy(genesis_block);
        free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        logger_log(LOG_LEVEL_FATAL, "Failed to add genesis block to blockchain.");
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Blockchain created with genesis block (Difficulty: %d).", bc->difficulty);
    print_green("Genesis Block (Block #0) created and mined successfully!\n"); // Using helper
    return bc;
}

/**
 * @brief Adds a new block to the blockchain.
 * This function now takes ownership of the new_block pointer.
 * @param blockchain The blockchain to add the block to.
 * @param new_block The block to be added (must be heap-allocated).
 * @return 0 on success, -1 on failure.
 */
int blockchain_add_block(Blockchain* blockchain, Block* new_block) {
    if (blockchain == NULL || new_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain or new_block is NULL in blockchain_add_block.");
        return -1;
    }

    if (blockchain->length == blockchain->capacity) {
        size_t new_capacity = blockchain->capacity * 2;
        if (new_capacity == 0) new_capacity = CHAIN_INITIAL_CAPACITY;

        Block** temp_chain = (Block**)realloc(blockchain->chain, new_capacity * sizeof(Block*));
        if (temp_chain == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for blockchain chain.");
            print_red("Failed to reallocate memory for blockchain chain.\n"); // Using helper
            return -1;
        }
        blockchain->chain = temp_chain;
        blockchain->capacity = new_capacity;
        logger_log(LOG_LEVEL_DEBUG, "Blockchain capacity increased to %zu.", new_capacity);
    }

    blockchain->chain[blockchain->length] = new_block;
    blockchain->length++;

    logger_log(LOG_LEVEL_INFO, "Block #%u added to the blockchain. Current length: %zu.",
               new_block->index, blockchain->length);
    // For mixed colors, you can still use multiple print calls or combine some ANSI codes manually if needed for precision.
    print_green("Block #%u added to the blockchain. ", new_block->index);
    printf("Current length: ");
    print_yellow("%zu\n", blockchain->length); // This breaks it into multiple calls.
    return 0;
}

/**
 * @brief Adds a transaction to the list of pending transactions.
 * @param blockchain The blockchain instance.
 * @param tx The transaction to add. The blockchain takes ownership of `tx`.
 * @return 0 on success, -1 on failure.
 */
int blockchain_add_transaction_to_pending(Blockchain* blockchain, Transaction* tx) {
    if (blockchain == NULL || tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain or transaction is NULL when adding to pending list.");
        return -1;
    }

    // Reallocate if capacity is full
    if (blockchain->num_pending_transactions == blockchain->pending_transactions_capacity) {
        size_t new_capacity = blockchain->pending_transactions_capacity * 2;
        if (new_capacity == 0) new_capacity = PENDING_TRANSACTIONS_INITIAL_CAPACITY; // Handle initial zero case

        Transaction** temp_tx = (Transaction**)realloc(blockchain->pending_transactions, new_capacity * sizeof(Transaction*));
        if (temp_tx == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for pending transactions.");
            print_red("Failed to reallocate memory for pending transactions.\n"); // Using helper
            return -1;
        }
        blockchain->pending_transactions = temp_tx;
        blockchain->pending_transactions_capacity = new_capacity;
        logger_log(LOG_LEVEL_DEBUG, "Pending transactions capacity increased to %zu.", new_capacity);
    }

    blockchain->pending_transactions[blockchain->num_pending_transactions] = tx;
    blockchain->num_pending_transactions++;
    logger_log(LOG_LEVEL_INFO, "Transaction added to pending list. Total pending: %zu.", blockchain->num_pending_transactions);
    print_green("Transaction added to pending list. ");
    printf("Total pending: ");
    print_yellow("%zu\n", blockchain->num_pending_transactions); // Breaks into multiple calls
    return 0;
}

/**
 * @brief Mines a new block with the current pending transactions.
 * After a successful mine, pending transactions are cleared.
 * @param blockchain The blockchain instance.
 * @return 0 on success, -1 on failure.
 */
int blockchain_mine_new_block(Blockchain* blockchain) {
    if (blockchain == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain is NULL when mining a new block.");
        return -1;
    }

    // Get the previous block's hash
    Block* last_block = blockchain->chain[blockchain->length - 1];
    if (last_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Last block is NULL, cannot mine a new block.");
        print_red("Error: Last block is NULL, cannot mine a new block.\n"); // Using helper
        return -1;
    }

    // Create a new block using the next index and the previous block's hash
    Block* new_block = block_create(last_block->index + 1, last_block->hash);
    if (new_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new block for mining.");
        print_red("Failed to create new block for mining.\n"); // Using helper
        return -1;
    }

    // Add pending transactions to the new block
    for (size_t i = 0; i < blockchain->num_pending_transactions; ++i) {
        if (blockchain->pending_transactions[i] != NULL) {
            if (block_add_transaction(new_block, blockchain->pending_transactions[i]) != 0) {
                logger_log(LOG_LEVEL_WARN, "Failed to add pending transaction %zu to new block. Continuing with others.", i);
                print_yellow("Warning: Failed to add pending transaction %zu to new block. Continuing.\n", i); // Using helper
                // The transaction remains in pending_transactions if adding to block fails, it's not destroyed here.
            } else {
                // Transaction successfully moved to new_block, set pending to NULL to prevent double-free
                blockchain->pending_transactions[i] = NULL;
            }
        }
    }

    // Mine the new block
    logger_log(LOG_LEVEL_INFO, "Attempting to mine new block #%u with %zu transactions...",
               new_block->index, new_block->num_transactions);
    print_cyan("Attempting to mine new block #%u with %zu transactions...\n",
           new_block->index, new_block->num_transactions); // Using helper

    if (block_mine(new_block, blockchain->difficulty) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to mine new block.");
        print_red("Failed to mine new block.\n"); // Using helper
        block_destroy(new_block); // Destroy the block if mining fails
        return -1;
    }

    // Add the mined block to the blockchain
    if (blockchain_add_block(blockchain, new_block) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to add mined block to the blockchain.");
        print_red("Failed to add mined block to the blockchain.\n"); // Using helper
        block_destroy(new_block);
        return -1;
    }

    // Clear pending transactions after successful mining
    for (size_t i = 0; i < blockchain->num_pending_transactions; ++i) {
        if (blockchain->pending_transactions[i] != NULL) {
            // Destroy any transactions that were not successfully added to the block
            transaction_destroy(blockchain->pending_transactions[i]);
            blockchain->pending_transactions[i] = NULL;
        }
    }
    blockchain->num_pending_transactions = 0; // Reset count
    logger_log(LOG_LEVEL_INFO, "Pending transactions cleared after mining block #%u.", new_block->index);
    print_green("Pending transactions cleared after mining block #%u.\n", new_block->index); // Using helper

    return 0;
}

/**
 * @brief Retrieves a block from the blockchain by its index.
 * @param blockchain The blockchain to query.
 * @param index The index of the block to retrieve.
 * @return A pointer to the Block at the specified index, or NULL if out of bounds.
 */
Block* blockchain_get_block_by_index(const Blockchain* blockchain, size_t index) {
    if (blockchain == NULL || index >= blockchain->length) {
        logger_log(LOG_LEVEL_ERROR, "Error: Invalid blockchain or index %zu (length %zu) in blockchain_get_block_by_index.",
                   index, blockchain ? blockchain->length : 0);
        return NULL;
    }
    return blockchain->chain[index];
}

/**
 * @brief Validates the entire blockchain.
 * @param blockchain The blockchain to validate.
 * @return 0 if valid, -1 if invalid.
 */
int blockchain_is_valid(const Blockchain* blockchain) {
    if (blockchain == NULL || blockchain->length == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid or empty blockchain provided for validation.");
        print_red("Invalid or empty blockchain provided for validation.\n"); // Using helper
        return -1;
    }

    uint8_t calculated_hash[BLOCK_HASH_SIZE]; // Buffer for calculated hashes

    print_cyan("Starting blockchain validation...\n"); // Using helper

    // The genesis block (index 0) must have a previous hash of all zeros
    if (memcmp(blockchain->chain[0]->prev_hash, GENESIS_PREV_HASH_BYTES, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid genesis block previous hash. Expected all zeros, Got %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->prev_hash, BLOCK_HASH_SIZE));
        print_red("Validation Failed: ");
        printf("Genesis block has incorrect previous hash.\n"); // Splitting for mixed color
        return -1;
    }

    // Validate genesis block's own hash by recalculating it
    if (block_calculate_hash(blockchain->chain[0], calculated_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for genesis block validation.");
        print_red("Validation Failed: ");
        printf("Failed to calculate hash for Genesis Block.\n"); // Splitting for mixed color
        return -1;
    }

    if (memcmp(blockchain->chain[0]->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block hash mismatch. Stored: %s, Recalculated: %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->hash, BLOCK_HASH_SIZE),
                   hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
        print_red("Validation Failed: ");
        printf("Genesis block hash mismatch.\n"); // Splitting for mixed color
        return -1;
    }

    // Validate Proof of Work for genesis block
    if (block_is_valid(blockchain->chain[0], blockchain->difficulty) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block is invalid (failed block_is_valid check).");
        print_red("Validation Failed: ");
        printf("Genesis block failed internal validation (PoW or transactions).\n"); // Splitting for mixed color
        return -1;
    }
    print_green("Genesis Block (#0) validated successfully.\n"); // Using helper


    // Iterate from the second block (index 1) to validate linkage and self-hashes
    for (size_t i = 1; i < blockchain->length; i++) {
        Block* current_block = blockchain->chain[i];
        Block* prev_block = blockchain->chain[i-1];

        print_cyan("  Validating Block #%u...\n", current_block->index); // Using helper

        // Validate current block's own hash by recalculating
        if (block_calculate_hash(current_block, calculated_hash) != 0) {
             logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for block #%u validation.", current_block->index);
             print_red("Validation Failed: ");
             printf("Failed to calculate hash for Block #%u.\n", current_block->index); // Splitting for mixed color
             return -1;
        }

        if (memcmp(current_block->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u hash mismatch. Stored: %s, Recalculated: %s.",
                       current_block->index,
                       hasher_bytes_to_hex(current_block->hash, BLOCK_HASH_SIZE),
                       hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
            print_red("Validation Failed: ");
            printf("Block #%u hash mismatch.\n", current_block->index); // Splitting for mixed color
            return -1;
        }

        // Validate previous hash linkage:
        if (memcmp(current_block->prev_hash, prev_block->hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u previous hash mismatch. Expected %s (from block %u), Got %s.",
                       current_block->index,
                       hasher_bytes_to_hex(prev_block->hash, BLOCK_HASH_SIZE),
                       prev_block->index,
                       hasher_bytes_to_hex(current_block->prev_hash, BLOCK_HASH_SIZE));
            print_red("Validation Failed: ");
            printf("Block #%u previous hash does not match Block #%u's hash.\n",
                   current_block->index, prev_block->index); // Splitting for mixed color
            return -1;
        }

        // Validate Proof of Work and transactions for current block
        if (block_is_valid(current_block, blockchain->difficulty) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u is invalid (failed block_is_valid check).", current_block->index);
            print_red("Validation Failed: ");
            printf("Block #%u is invalid (failed internal validation).\n", current_block->index); // Splitting for mixed color
            return -1;
        }
        print_green("  Block #%u validated successfully.\n", current_block->index); // Using helper
    }

    print_green("Blockchain is valid.\n"); // Using helper
    return 0;
}

/**
 * @brief Frees all memory allocated for the blockchain.
 * @param blockchain A pointer to the Blockchain to destroy.
 */
void blockchain_destroy(Blockchain* blockchain) {
    if (blockchain == NULL) {
        return;
    }

    print_cyan("Destroying blockchain...\n"); // Using helper

    if (blockchain->chain != NULL) {
        for (size_t i = 0; i < blockchain->length; i++) {
            if (blockchain->chain[i] != NULL) {
                block_destroy(blockchain->chain[i]);
            }
        }
        free(blockchain->chain);
        blockchain->chain = NULL;
    }

    if (blockchain->pending_transactions != NULL) {
        for (size_t i = 0; i < blockchain->num_pending_transactions; i++) {
            if (blockchain->pending_transactions[i] != NULL) {
                transaction_destroy(blockchain->pending_transactions[i]);
            }
        }
        free(blockchain->pending_transactions);
        blockchain->pending_transactions = NULL;
    }

    free(blockchain);
    print_cyan("Blockchain destroyed.\n"); // Using helper
}
