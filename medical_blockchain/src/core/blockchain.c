// src/core/blockchain.c
#include "core/blockchain.h"
#include "core/block.h"
#include "core/transaction.h"
#include "core/mempool.h"     // Included to access global mempool functions
#include "utils/logger.h"
#include "utils/colors.h"
#include "crypto/hasher.h"
#include "mining/proof_of_work.h"
#include "config/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHAIN_INITIAL_CAPACITY 10

static const uint8_t GENESIS_PREV_HASH_BYTES[BLOCK_HASH_SIZE] = {0};

/**
 * @brief Creates a new blockchain instance, including the genesis block.
 *
 * This function initializes the blockchain structure, allocates memory for
 * the chain, creates a genesis block (Block #0), mines it, and adds it to the blockchain.
 * Note: The `pending_transactions` members of the Blockchain struct are no longer
 * directly used for mining, as transactions are now managed by the global `mempool` module.
 *
 * @return A pointer to the newly created Blockchain object on success, or NULL on failure.
 */
Blockchain* blockchain_create() {
    Blockchain* bc = (Blockchain*)malloc(sizeof(Blockchain));
    if (bc == NULL) {
        print_red("Failed to allocate memory for Blockchain\n");
        return NULL;
    }

    bc->chain = (Block**)malloc(sizeof(Block*) * CHAIN_INITIAL_CAPACITY);
    if (bc->chain == NULL) {
        print_red("Failed to allocate memory for blockchain chain (array of Block pointers)\n");
        free(bc);
        return NULL;
    }
    bc->capacity = CHAIN_INITIAL_CAPACITY;
    bc->length = 0;
    bc->difficulty = DEFAULT_DIFFICULTY;

    // These members of the Blockchain struct are now effectively unused for mining
    // as transactions are managed by the global mempool. They are kept for struct
    // compatibility but will not be populated by `add-transaction` or used by `mine-block`.
    bc->pending_transactions = NULL;
    bc->pending_transactions_capacity = 0;
    bc->num_pending_transactions = 0;

    Block* genesis_block = block_create(0, GENESIS_PREV_HASH_BYTES);
    if (genesis_block == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create genesis block.");
        // If pending_transactions was ever allocated, free it here, though it should be NULL.
        if (bc->pending_transactions) free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Mining Genesis Block (Block #0) with difficulty %d...", DEFAULT_DIFFICULTY);
    if (block_mine(genesis_block, DEFAULT_DIFFICULTY) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to mine genesis block.");
        block_destroy(genesis_block);
        if (bc->pending_transactions) free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        return NULL;
    }

    if (blockchain_add_block(bc, genesis_block) != 0) {
        block_destroy(genesis_block);
        if (bc->pending_transactions) free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        logger_log(LOG_LEVEL_FATAL, "Failed to add genesis block to blockchain.");
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Blockchain created with genesis block (Difficulty: %d).", bc->difficulty);
    print_green("Genesis Block (Block #0) created and mined successfully!\n");
    return bc;
}

/**
 * @brief Adds a mined block to the blockchain.
 *
 * This function handles the dynamic resizing of the blockchain's internal
 * array if necessary, and then appends the new block.
 *
 * @param blockchain A pointer to the Blockchain instance.
 * @param new_block A pointer to the Block to be added. The blockchain takes ownership of this pointer.
 * @return 0 on success, -1 on failure (e.g., NULL input, memory reallocation failure).
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
            print_red("Failed to reallocate memory for blockchain chain.\n");
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
    print_green("Block #%u added to the blockchain. ", new_block->index);
    printf("Current length: ");
    print_yellow("%zu\n", blockchain->length);
    return 0;
}

/**
 * @brief Adds a transaction to the blockchain's pending transaction pool (mempool).
 *
 * This function's primary purpose is to add transactions to the *global* mempool.
 * The `Blockchain` struct itself no longer directly manages its own pending transactions
 * for mining purposes. This function now explicitly calls the global `mempool_add_transaction`.
 *
 * @param blockchain A pointer to the Blockchain instance (used for context, but pending txns are global).
 * @param tx A pointer to the Transaction to be added. The global mempool takes ownership of this pointer.
 * @return 0 on success, -1 on failure.
 */
int blockchain_add_transaction_to_pending(Blockchain* blockchain, Transaction* tx) {
    if (blockchain == NULL || tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain or transaction is NULL when adding to pending list.");
        return -1;
    }

    // Delegate to the global mempool module
    if (mempool_add_transaction(tx) == false) {
        logger_log(LOG_LEVEL_ERROR, "Failed to add transaction to global mempool (full or duplicate).");
        print_red("Failed to add transaction to mempool (mempool full or duplicate).\n");
        return -1;
    }

    logger_log(LOG_LEVEL_INFO, "Transaction added to global mempool. Total pending: %zu.", mempool_get_size());
    print_green("Transaction added to pending list. ");
    printf("Total pending: ");
    print_yellow("%zu\n", mempool_get_size());
    return 0;
}


/**
 * @brief Mines a new block, attempting to include pending transactions from the global mempool.
 *
 * This function creates a new block, retrieves all currently pending transactions
 * from the global mempool, adds them to the new block, mines the block (Proof-of-Work),
 * and then adds the successfully mined block to the blockchain. Finally,
 * it clears the global pending transaction pool.
 *
 * @param blockchain A pointer to the Blockchain instance.
 * @return 0 on success, -1 on failure (e.g., NULL input, last block not found, block creation/mining/adding fails).
 */
int blockchain_mine_new_block(Blockchain* blockchain) {
    if (blockchain == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain is NULL when mining a new block.");
        return -1;
    }

    // DEBUGGING LINE: This log confirms the `blockchain` struct's internal pending count,
    // which should typically be 0 if the global mempool is used correctly.
    logger_log(LOG_LEVEL_DEBUG, "DEBUG: Entering blockchain_mine_new_block. Current pending transactions (from Blockchain struct): %zu", blockchain->num_pending_transactions);
    print_blue("DEBUG: Entering mine-block. Pending (from Blockchain struct): %zu\n", blockchain->num_pending_transactions);


    Block* last_block = blockchain->chain[blockchain->length - 1];
    if (last_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Last block is NULL, cannot mine a new block.");
        print_red("Error: Last block is NULL, cannot mine a new block.\n");
        return -1;
    }

    Block* new_block = block_create(last_block->index + 1, last_block->hash);
    if (new_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new block for mining.");
        print_red("Failed to create new block for mining.\n");
        return -1;
    }

    // --- FIX: Get transactions from the GLOBAL mempool module and add them to the new block ---
    size_t num_mempool_tx_current = mempool_get_size();
    Transaction** transactions_to_mine = NULL; // This will hold pointers to transactions

    if (num_mempool_tx_current > 0) {
        transactions_to_mine = (Transaction**)malloc(num_mempool_tx_current * sizeof(Transaction*));
        if (transactions_to_mine == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to allocate memory for copying mempool transactions for mining.");
            print_red("Failed to allocate memory for copying mempool transactions for mining.\n");
            block_destroy(new_block);
            return -1;
        }
        // Use mempool_get_transactions_for_block to get all current pending transactions.
        // It populates `transactions_to_mine` and returns the actual count copied.
        num_mempool_tx_current = mempool_get_transactions_for_block(num_mempool_tx_current, transactions_to_mine);
        // Note: mempool_get_transactions_for_block does NOT remove from mempool.
        // It copies pointers, so mempool still holds them until mempool_clear().
    }

    logger_log(LOG_LEVEL_INFO, "Attempting to mine new block #%u. Pulled %zu transactions from global mempool.",
               new_block->index, num_mempool_tx_current);
    print_cyan("Attempting to mine new block #%u. Pulled %zu transactions from global mempool.\n",
               new_block->index, num_mempool_tx_current);

    // Add transactions from the temporary array (copied from mempool) to the new block.
    // block_add_transaction is assumed to take ownership of the Transaction* pointer
    // and correctly manage its lifecycle (e.g., make a copy or take full responsibility for freeing).
    for (size_t i = 0; i < num_mempool_tx_current; ++i) {
        if (transactions_to_mine[i] != NULL) {
            if (block_add_transaction(new_block, transactions_to_mine[i]) != 0) {
                logger_log(LOG_LEVEL_WARN, "Failed to add mempool transaction %s to new block. Continuing with others.",
                           transactions_to_mine[i]->transaction_id);
                print_yellow("Warning: Failed to add mempool transaction %s to new block. Continuing.\n",
                             transactions_to_mine[i]->transaction_id);
                // If it fails to add to block, the transaction pointer is still in `transactions_to_mine`.
                // We need to destroy it now to prevent a memory leak, as it won't be in the block.
                transaction_destroy(transactions_to_mine[i]);
            }
            // If block_add_transaction succeeds, it is assumed to take ownership and lifecycle management.
            // No need to NULL out `transactions_to_mine[i]` here if block_add_transaction is robust.
            // If block_add_transaction makes a deep copy, then `transactions_to_mine[i]` should also be destroyed here.
            // Given the original `blockchain_mine_new_block` logic, it expects to pass ownership.
        } else {
            logger_log(LOG_LEVEL_WARN, "NULL transaction pointer found in mempool copy at index %zu. Skipping.", i);
        }
    }

    // Free the temporary array of pointers. The transactions themselves are either
    // now owned by `new_block` (if added) or were destroyed (if `block_add_transaction` failed for them).
    if (transactions_to_mine) {
        free(transactions_to_mine);
        transactions_to_mine = NULL;
    }
    // --- END FIX: Transactions are now in new_block ---


    logger_log(LOG_LEVEL_INFO, "Attempting to mine new block #%u with %zu transactions (now in block struct)...",
               new_block->index, new_block->num_transactions);
    print_cyan("Attempting to mine new block #%u with %zu transactions (now in block struct)...\n",
               new_block->index, new_block->num_transactions);


    if (block_mine(new_block, blockchain->difficulty) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to mine new block.");
        print_red("Failed to mine new block.\n");
        block_destroy(new_block); // This will free transactions that were successfully added to new_block
        // If mining fails, transactions originally in mempool are still there.
        // A more robust system might attempt to re-add transactions from the *failed* new_block
        // back to the mempool, but for this fix, we simply clear the mempool afterward.
        return -1;
    }

    if (blockchain_add_block(blockchain, new_block) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to add mined block to the blockchain.");
        print_red("Failed to add mined block to the blockchain.\n");
        block_destroy(new_block); // This will free transactions that were added to new_block
        return -1;
    }

    // --- FIX: Clear the global mempool after successful mining and block addition ---
    // This clears the mempool's internal list of transaction pointers.
    // The actual Transaction objects are now managed by the `new_block` which has taken ownership.
    mempool_clear();
    logger_log(LOG_LEVEL_INFO, "Global mempool cleared after mining block #%u.", new_block->index);
    print_green("Global mempool cleared after mining block #%u.\n", new_block->index);

    // The `blockchain->num_pending_transactions = 0;` and related loop for `blockchain->pending_transactions`
    // are no longer needed here as the global mempool is now handled directly.
    // The `blockchain` struct's `pending_transactions` members are now effectively unused for mining logic.

    return 0;
}

/**
 * @brief Retrieves a block from the blockchain by its index.
 *
 * @param blockchain A pointer to the constant Blockchain instance.
 * @param index The zero-based index of the block to retrieve.
 * @return A pointer to the Block on success, or NULL if the index is out of bounds or blockchain is NULL.
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
 * @brief Retrieves a block from the blockchain by its hash.
 *
 * @param blockchain A pointer to the constant Blockchain instance.
 * @param hash_hex The hexadecimal string representation of the block's hash.
 * @return A pointer to the Block on success, or NULL if not found, invalid hash, or blockchain is NULL.
 */
Block* blockchain_get_block_by_hash(const Blockchain* blockchain, const char* hash_hex) {
    if (blockchain == NULL || hash_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Invalid blockchain or hash_hex is NULL in blockchain_get_block_by_hash.");
        return NULL;
    }

    uint8_t target_hash_bytes[BLOCK_HASH_SIZE];
    if (hasher_hex_to_bytes_buf(hash_hex, target_hash_bytes, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid hash hex string provided for lookup in blockchain_get_block_by_hash.");
        return NULL;
    }

    for (size_t i = 0; i < blockchain->length; ++i) {
        // Ensure the stored block hash is also in bytes for memcmp
        if (memcmp(blockchain->chain[i]->hash, target_hash_bytes, BLOCK_HASH_SIZE) == 0) {
            return blockchain->chain[i];
        }
    }

    logger_log(LOG_LEVEL_INFO, "Block with hash %s not found.", hash_hex);
    return NULL;
}

/**
 * @brief Retrieves a transaction from the entire blockchain by its ID.
 *
 * This function iterates through all blocks and their transactions to find a matching transaction ID.
 *
 * @param blockchain A pointer to the constant Blockchain instance.
 * @param transaction_id_hex The hexadecimal string representation of the transaction's ID.
 * @return A pointer to the constant Transaction on success, or NULL if not found or inputs are NULL.
 */
const Transaction* blockchain_get_transaction(const Blockchain* blockchain, const char* transaction_id_hex) {
    if (blockchain == NULL || transaction_id_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Invalid blockchain or transaction_id_hex is NULL in blockchain_get_transaction.");
        return NULL;
    }

    // The transaction ID in the struct is already a hex string (char array)
    // We can directly compare it with the provided transaction_id_hex
    for (size_t i = 0; i < blockchain->length; ++i) {
        Block* current_block = blockchain->chain[i];
        for (size_t j = 0; j < current_block->num_transactions; ++j) {
            const Transaction* tx = current_block->transactions[j];
            // Compare the transaction_id string directly
            if (strcmp(tx->transaction_id, transaction_id_hex) == 0) {
                return tx;
            }
        }
    }

    logger_log(LOG_LEVEL_INFO, "Transaction with ID %s not found.", transaction_id_hex);
    return NULL;
}

/**
 * @brief Validates the integrity and correctness of the entire blockchain.
 *
 * This function checks:
 * - The genesis block's previous hash and its own hash.
 * - The proof-of-work for all blocks.
 * - The chronological order of block indices.
 * - The link between consecutive blocks (current block's prev_hash matches previous block's hash).
 * - The validity of all transactions within each block (assuming `block_is_valid` does this).
 *
 * @param blockchain A pointer to the constant Blockchain instance.
 * @return 0 if the blockchain is valid, -1 if any validation check fails.
 */
int blockchain_is_valid(const Blockchain* blockchain) {
    if (blockchain == NULL || blockchain->length == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid or empty blockchain provided for validation.");
        print_red("Invalid or empty blockchain provided for validation.\n");
        return -1;
    }

    uint8_t calculated_hash[BLOCK_HASH_SIZE];

    print_cyan("Starting blockchain validation...\n");

    // Validate Genesis Block
    if (memcmp(blockchain->chain[0]->prev_hash, GENESIS_PREV_HASH_BYTES, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid genesis block previous hash. Expected all zeros, Got %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->prev_hash, BLOCK_HASH_SIZE));
        print_red("Validation Failed: Genesis block has incorrect previous hash.\n");
        return -1;
    }

    if (block_calculate_hash(blockchain->chain[0], calculated_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for genesis block validation.");
        print_red("Validation Failed: Failed to calculate hash for Genesis Block.\n");
        return -1;
    }

    if (memcmp(blockchain->chain[0]->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block hash mismatch. Stored: %s, Recalculated: %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->hash, BLOCK_HASH_SIZE),
                   hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
        print_red("Validation Failed: Genesis block hash mismatch.\n");
        return -1;
    }

    if (block_is_valid(blockchain->chain[0], blockchain->difficulty) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block is invalid (failed block_is_valid check).");
        print_red("Validation Failed: Genesis block failed internal validation (PoW or transactions).\n");
        return -1;
    }
    print_green("Genesis Block (#0) validated successfully.\n");

    // Validate subsequent blocks
    for (size_t i = 1; i < blockchain->length; i++) {
        Block* current_block = blockchain->chain[i];
        Block* prev_block = blockchain->chain[i-1];

        print_cyan("  Validating Block #%u...\n", current_block->index);

        if (current_block->index != prev_block->index + 1) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u has invalid index. Expected %u, Got %u.",
                       current_block->index, prev_block->index + 1, current_block->index);
            print_red("Validation Failed: Block #%u has invalid index.\n", current_block->index);
            return -1;
        }

        if (block_calculate_hash(current_block, calculated_hash) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for block #%u validation.", current_block->index);
            print_red("Validation Failed: Failed to calculate hash for Block #%u.\n", current_block->index);
            return -1;
        }

        if (memcmp(current_block->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u hash mismatch. Stored: %s, Recalculated: %s.",
                       current_block->index,
                       hasher_bytes_to_hex(current_block->hash, BLOCK_HASH_SIZE),
                       hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
            print_red("Validation Failed: Block #%u hash mismatch.\n", current_block->index);
            return -1;
        }

        if (memcmp(current_block->prev_hash, prev_block->hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u previous hash mismatch. Expected %s (from block %u), Got %s.",
                       current_block->index,
                       hasher_bytes_to_hex(prev_block->hash, BLOCK_HASH_SIZE),
                       prev_block->index,
                       hasher_bytes_to_hex(current_block->prev_hash, BLOCK_HASH_SIZE));
            print_red("Validation Failed: Block #%u previous hash does not match Block #%u's hash.\n",
                      current_block->index, prev_block->index);
            return -1;
        }

        if (block_is_valid(current_block, blockchain->difficulty) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u is invalid (failed block_is_valid check).", current_block->index);
            print_red("Validation Failed: Block #%u is invalid (failed internal validation).\n", current_block->index);
            return -1;
        }
        print_green("  Block #%u validated successfully.\n", current_block->index);
    }

    print_green("Blockchain is valid.\n");
    return 0;
}

/**
 * @brief Destroys a blockchain instance and frees all associated memory.
 *
 * This includes freeing all blocks in the chain and any remaining pending transactions
 * that might have been managed internally (though the global mempool is now primary).
 * It's crucial to call this function when the blockchain is no longer needed to prevent memory leaks.
 *
 * @param blockchain A pointer to the Blockchain instance to be destroyed.
 */
void blockchain_destroy(Blockchain* blockchain) {
    if (blockchain == NULL) {
        return;
    }

    print_cyan("Destroying blockchain...\n");

    // Free all blocks in the main chain.
    if (blockchain->chain != NULL) {
        for (size_t i = 0; i < blockchain->length; i++) {
            if (blockchain->chain[i] != NULL) {
                block_destroy(blockchain->chain[i]);
            }
        }
        free(blockchain->chain);
        blockchain->chain = NULL;
    }

    // Free any remaining transactions in the pending pool of the blockchain struct itself.
    // This loop primarily handles transactions that might have been added to this internal
    // array if `blockchain_add_transaction_to_pending` was used for its internal members.
    // Given the new design, this array should ideally be empty or not used.
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
    print_cyan("Blockchain destroyed.\n");
}

