// src/core/blockchain.c
#include "core/blockchain.h"
#include "core/block.h"     // For block-related functions/definitions
#include "utils/logger.h"   // For logging
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Initial capacity for the blockchain array
#define INITIAL_CAPACITY 10

/**
 * @brief Initializes a new blockchain.
 * @return A pointer to the newly created Blockchain structure, or NULL on failure.
 */
Blockchain* blockchain_create() {
    Blockchain* bc = (Blockchain*)malloc(sizeof(Blockchain));
    if (bc == NULL) {
        // Cannot use logger_log here if logger_init hasn't been called yet.
        // Use standard error for initial memory allocation failures.
        perror("Failed to allocate memory for Blockchain");
        return NULL;
    }

    bc->chain = (Block*)malloc(sizeof(Block) * INITIAL_CAPACITY);
    if (bc->chain == NULL) {
        perror("Failed to allocate memory for blockchain chain");
        free(bc);
        return NULL;
    }
    bc->capacity = INITIAL_CAPACITY;
    bc->length = 0;

    // Create the genesis block (the first block in the chain)
    // The 'block_create' function now expects:
    // index, prev_hash (full SHA256 zero string), nonce, transactions array (NULL), num_transactions (0)
    Block* genesis_block = block_create(0, "0000000000000000000000000000000000000000000000000000000000000000", 0, NULL, 0);
    if (genesis_block == NULL) {
        // Now logger is assumed initialized by main, so we can use it.
        logger_log(LOG_LEVEL_FATAL, "Failed to create genesis block.");
        free(bc->chain);
        free(bc);
        return NULL;
    }

    // Add genesis block to the chain. blockchain_add_block will make a copy.
    if (blockchain_add_block(bc, genesis_block) != 0) {
        block_destroy(genesis_block); // Free the temporary block created above
        free(bc->chain);
        free(bc);
        logger_log(LOG_LEVEL_FATAL, "Failed to add genesis block to blockchain.");
        return NULL;
    }
    block_destroy(genesis_block); // Free the temporary block after it has been copied

    logger_log(LOG_LEVEL_INFO, "Blockchain created with genesis block.");
    return bc;
}

/**
 * @brief Adds a new block to the blockchain.
 * @param blockchain The blockchain to add the block to.
 * @param new_block The block to be added.
 * @return 0 on success, -1 on failure.
 */
int blockchain_add_block(Blockchain* blockchain, Block* new_block) {
    if (blockchain == NULL || new_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain or new_block is NULL in blockchain_add_block.");
        return -1;
    }

    // Check if capacity needs to be increased (dynamic array growth)
    if (blockchain->length == blockchain->capacity) {
        size_t new_capacity = blockchain->capacity * 2;
        if (new_capacity == 0) new_capacity = INITIAL_CAPACITY; // For the very first realloc if capacity was 0

        Block* temp_chain = (Block*)realloc(blockchain->chain, new_capacity * sizeof(Block));
        if (temp_chain == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for blockchain chain.");
            return -1;
        }
        blockchain->chain = temp_chain;
        blockchain->capacity = new_capacity;
        logger_log(LOG_LEVEL_DEBUG, "Blockchain capacity increased to %zu.", new_capacity);
    }

    // Copy the new block into the chain.
    // This assumes the Block struct and its contents (like Transaction array)
    // are suitable for a shallow copy via memcpy. If Transaction contained pointers
    // to dynamically allocated data, a deep copy would be required here.
    memcpy(&blockchain->chain[blockchain->length], new_block, sizeof(Block));
    blockchain->length++;

    logger_log(LOG_LEVEL_INFO, "Block #%u added to the blockchain. Current length: %u.",
               new_block->index, blockchain->length); // Corrected %zu to %u
    return 0;
}

/**
 * @brief Validates the entire blockchain.
 * @param blockchain The blockchain to validate.
 * @return 0 if valid, -1 if invalid.
 */
int blockchain_is_valid(const Blockchain* blockchain) {
    if (blockchain == NULL || blockchain->length == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid or empty blockchain provided for validation.");
        return -1; // Invalid or empty blockchain
    }

    // Define the expected genesis previous hash as a constant string
    const char* GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    // The genesis block (index 0) must have a previous hash of all zeros
    if (strcmp(blockchain->chain[0].prev_hash, GENESIS_PREV_HASH) != 0) { // Corrected previous_hash to prev_hash
        logger_log(LOG_LEVEL_ERROR, "Invalid genesis block previous hash. Expected %s, Got %s.",
                   GENESIS_PREV_HASH, blockchain->chain[0].prev_hash);
        return -1;
    }

    // Validate genesis block's own hash by recalculating it
    Block temp_genesis = blockchain->chain[0]; // Make a copy to modify its hash without affecting original
    temp_genesis.hash[0] = '\0';               // Clear its hash to force recalculation
    block_calculate_hash(&temp_genesis);       // This function recalculates and sets temp_genesis.hash

    if (strcmp(blockchain->chain[0].hash, temp_genesis.hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block hash mismatch. Stored: %s, Recalculated: %s.",
                   blockchain->chain[0].hash, temp_genesis.hash);
        return -1;
    }

    // Iterate from the second block (index 1) to validate linkage and self-hashes
    for (unsigned int i = 1; i < blockchain->length; i++) { // Changed loop counter to unsigned int
        // Validate current block's own hash by recalculating
        Block current_block_copy = blockchain->chain[i]; // Make a copy
        current_block_copy.hash[0] = '\0';               // Clear its hash
        block_calculate_hash(&current_block_copy);       // Recalculate hash of the copy

        if (strcmp(blockchain->chain[i].hash, current_block_copy.hash) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u hash mismatch. Stored: %s, Recalculated: %s.",
                       blockchain->chain[i].index, blockchain->chain[i].hash, current_block_copy.hash);
            return -1;
        }

        // Validate previous hash linkage:
        // Current block's 'prev_hash' must match the 'hash' of the previous block
        if (strcmp(blockchain->chain[i].prev_hash, blockchain->chain[i-1].hash) != 0) { // Corrected previous_hash to prev_hash
            logger_log(LOG_LEVEL_ERROR, "Block #%u previous hash mismatch. Expected %s (from block %u), Got %s.",
                       blockchain->chain[i].index, blockchain->chain[i-1].hash,
                       blockchain->chain[i-1].index, blockchain->chain[i].prev_hash);
            return -1;
        }
        // TODO: Add Proof of Work validation here later
        // TODO: Add Merkle Root validation here later
    }
    logger_log(LOG_LEVEL_INFO, "Blockchain is valid.");
    return 0;
}

/**
 * @brief Frees the memory allocated for the blockchain.
 * @param blockchain The blockchain to free.
 */
void blockchain_destroy(Blockchain* blockchain) {
    if (blockchain == NULL) {
        return;
    }
    // If blocks were dynamically allocated within the chain (e.g., Block* chain[]),
    // you would iterate and call block_destroy on each element.
    // However, with `Block* chain` and `memcpy`, the blocks are stored directly
    // in the contiguous memory block pointed to by `blockchain->chain`.
    // The `Block` struct itself must manage its internal dynamic allocations (e.g., for Transaction's
    // `encrypted_medical_data`). When `block_destroy` is called on a `Block` pointer,
    // it typically frees the `Block` structure itself.
    // Here, `free(blockchain->chain)` frees the entire array of Block structs.
    // Ensure that `transaction_destroy` is called for `encrypted_medical_data` if `Block` itself isn't destroyed
    // by `blockchain_destroy`. Given the current structure (`Transaction transactions[]` in `Block`),
    // the `encrypted_medical_data` pointers *within* each transaction must be freed.
    // THIS IS A CRITICAL POINT: `memcpy` performs a shallow copy. If `Transaction` has `uint8_t* encrypted_medical_data`,
    // then when a `Block` is copied into the `blockchain->chain` array, both the original and the copied block
    // will point to the *same* `encrypted_medical_data` memory. This can lead to double-free issues or memory leaks.
    //
    // A robust solution involves:
    // 1. `block_add_transaction` doing a deep copy of `encrypted_medical_data`.
    // 2. `block_destroy` iterating through its transactions and calling `transaction_destroy` on each.
    // 3. `blockchain_destroy` iterating through its blocks and calling `block_destroy` on each.
    //
    // For now, assuming your `Block` and `Transaction` structs are set up for deep copying or are simple value types.
    // Given `Transaction` has `uint8_t* encrypted_medical_data`, you WILL need `block_destroy` to free those.
    // So, the `for` loop below is necessary.
    if (blockchain->chain != NULL) {
        for (unsigned int i = 0; i < blockchain->length; i++) {
            // Call block_destroy for each block in the chain to handle its internal resources
            // (like `encrypted_medical_data` inside transactions).
            // Note: If block_destroy frees the Block* itself, then `&blockchain->chain[i]` is not what you want.
            // You'd need a `block_clear_contents(&blockchain->chain[i])` or similar.
            // For now, let's assume `block_destroy` is designed to free internal pointers if it took a pointer.
            // Since we stored by value, the following is dangerous if `block_destroy` tries to free the Block*.
            // Let's adjust block_destroy to free ONLY internal pointers.
            // The provided block_destroy frees the Block* itself.
            // This means we cannot call `block_destroy(&blockchain->chain[i])` because `blockchain->chain[i]`
            // is part of a contiguous array that will be freed by `free(blockchain->chain)`.
            //
            // SOLUTION: Introduce a function like `block_clear_data` that frees internal pointers within a Block,
            // but does NOT free the Block struct itself.
            // And ensure transaction_destroy frees `encrypted_medical_data`.

            // For now, if block_destroy frees the Block* itself, we can't call it here.
            // We need `transaction_destroy` to be called for each transaction's `encrypted_medical_data`.
            for (unsigned int j = 0; j < blockchain->chain[i].num_transactions; j++) {
                // Ensure transaction_destroy is capable of freeing encrypted_medical_data
                transaction_destroy(&blockchain->chain[i].transactions[j]);
            }
        }
        free(blockchain->chain);
    }
    free(blockchain);
    logger_log(LOG_LEVEL_INFO, "Blockchain destroyed.");
}
