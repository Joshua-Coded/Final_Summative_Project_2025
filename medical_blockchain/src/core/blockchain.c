// src/core/blockchain.c
#include "blockchain.h"
#include "block.h"      // For block-related functions/definitions
#include "transaction.h"  // For transaction_destroy, transaction_is_valid
#include "../utils/logger.h" // For logging
#include "../crypto/hasher.h" // For BLOCK_HASH_SIZE, hasher_bytes_to_hex
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Initial capacity for the blockchain array of Block* pointers
#define INITIAL_CAPACITY 10

// Define the previous hash for the genesis block (all zeros in binary)
// This needs to be a uint8_t array to match the block_create function signature.
// BLOCK_HASH_SIZE is 32 bytes for SHA256.
static const uint8_t GENESIS_PREV_HASH_BYTES[BLOCK_HASH_SIZE] = {0}; // All 32 bytes are initialized to 0

/**
 * @brief Initializes a new blockchain.
 * @return A pointer to the newly created Blockchain structure, or NULL on failure.
 */
Blockchain* blockchain_create() {
    Blockchain* bc = (Blockchain*)malloc(sizeof(Blockchain));
    if (bc == NULL) {
        perror("Failed to allocate memory for Blockchain"); // Use perror before logger is initialized
        return NULL;
    }

    // Allocate memory for an array of Block* pointers
    bc->chain = (Block**)malloc(sizeof(Block*) * INITIAL_CAPACITY); // CRITICAL FIX: Block**
    if (bc->chain == NULL) {
        perror("Failed to allocate memory for blockchain chain (array of Block pointers)");
        free(bc);
        return NULL;
    }
    bc->capacity = INITIAL_CAPACITY;
    bc->length = 0;

    // Create the genesis block (the first block in the chain)
    // The previous hash is now passed as a uint8_t array.
    Block* genesis_block = block_create(0, GENESIS_PREV_HASH_BYTES); // FIX: Use byte array
    if (genesis_block == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create genesis block.");
        free(bc->chain);
        free(bc);
        return NULL;
    }

    // Mine the genesis block (assuming DEFAULT_DIFFICULTY is in config.h)
    // You need to decide where DEFAULT_DIFFICULTY comes from (config.h or another constant).
    // Assuming it's in config.h and correctly included.
    if (block_mine(genesis_block, DEFAULT_DIFFICULTY) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to mine genesis block.");
        block_destroy(genesis_block);
        free(bc->chain);
        free(bc);
        return NULL;
    }

    // Add genesis block to the chain. blockchain_add_block now takes ownership of genesis_block.
    if (blockchain_add_block(bc, genesis_block) != 0) {
        block_destroy(genesis_block); // Free the block if adding fails
        free(bc->chain);
        free(bc);
        logger_log(LOG_LEVEL_FATAL, "Failed to add genesis block to blockchain.");
        return NULL;
    }
    // DO NOT block_destroy(genesis_block) here. blockchain_add_block now owns it.

    logger_log(LOG_LEVEL_INFO, "Blockchain created with genesis block.");
    return bc;
}

/**
 * @brief Adds a new block to the blockchain.
 * This function now takes ownership of the new_block pointer, so the caller
 * should not free new_block after calling this function (unless it returns -1).
 * @param blockchain The blockchain to add the block to.
 * @param new_block The block to be added (must be heap-allocated).
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
        if (new_capacity == 0) new_capacity = INITIAL_CAPACITY; // Handle initial case if capacity was 0

        Block** temp_chain = (Block**)realloc(blockchain->chain, new_capacity * sizeof(Block*)); // FIX: Block**
        if (temp_chain == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for blockchain chain.");
            return -1;
        }
        blockchain->chain = temp_chain;
        blockchain->capacity = new_capacity;
        logger_log(LOG_LEVEL_DEBUG, "Blockchain capacity increased to %zu.", new_capacity);
    }

    // Store the pointer to the new block. The blockchain now "owns" this block.
    blockchain->chain[blockchain->length] = new_block; // FIX: Assign pointer directly
    blockchain->length++;

    logger_log(LOG_LEVEL_INFO, "Block #%u added to the blockchain. Current length: %zu.",
               new_block->index, blockchain->length); // Corrected %u to %zu for size_t length
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

    uint8_t calculated_hash[BLOCK_HASH_SIZE]; // Buffer for calculated hashes

    // The genesis block (index 0) must have a previous hash of all zeros
    // FIX: Use memcmp for byte arrays
    if (memcmp(blockchain->chain[0]->prev_hash, GENESIS_PREV_HASH_BYTES, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid genesis block previous hash. Expected all zeros, Got %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->prev_hash, BLOCK_HASH_SIZE));
        return -1;
    }

    // Validate genesis block's own hash by recalculating it
    // FIX: Pass output buffer to block_calculate_hash
    if (block_calculate_hash(blockchain->chain[0], calculated_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for genesis block validation.");
        return -1;
    }

    // FIX: Use memcmp for byte arrays
    if (memcmp(blockchain->chain[0]->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block hash mismatch. Stored: %s, Recalculated: %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->hash, BLOCK_HASH_SIZE),
                   hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
        return -1;
    }

    // Iterate from the second block (index 1) to validate linkage and self-hashes
    for (size_t i = 1; i < blockchain->length; i++) { // Changed loop counter to size_t
        // Validate current block's own hash by recalculating
        // FIX: Pass output buffer to block_calculate_hash
        if (block_calculate_hash(blockchain->chain[i], calculated_hash) != 0) {
             logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for block #%u validation.", blockchain->chain[i]->index);
             return -1;
        }

        // FIX: Use memcmp for byte arrays
        if (memcmp(blockchain->chain[i]->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u hash mismatch. Stored: %s, Recalculated: %s.",
                       blockchain->chain[i]->index,
                       hasher_bytes_to_hex(blockchain->chain[i]->hash, BLOCK_HASH_SIZE),
                       hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
            return -1;
        }

        // Validate previous hash linkage:
        // Current block's 'prev_hash' must match the 'hash' of the previous block
        // FIX: Use memcmp for byte arrays
        if (memcmp(blockchain->chain[i]->prev_hash, blockchain->chain[i-1]->hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u previous hash mismatch. Expected %s (from block %u), Got %s.",
                       blockchain->chain[i]->index,
                       hasher_bytes_to_hex(blockchain->chain[i-1]->hash, BLOCK_HASH_SIZE),
                       blockchain->chain[i-1]->index,
                       hasher_bytes_to_hex(blockchain->chain[i]->prev_hash, BLOCK_HASH_SIZE));
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
 * Iterates through each block pointer in the chain and calls block_destroy on it,
 * then frees the array of block pointers itself, and finally the Blockchain struct.
 * @param blockchain The blockchain to free.
 */
void blockchain_destroy(Blockchain* blockchain) {
    if (blockchain == NULL) {
        return;
    }

    if (blockchain->chain != NULL) {
        for (size_t i = 0; i < blockchain->length; i++) {
            // Call block_destroy for each block pointer in the chain.
            // block_destroy handles freeing the Block struct and its internal transactions.
            if (blockchain->chain[i] != NULL) {
                block_destroy(blockchain->chain[i]);
                blockchain->chain[i] = NULL; // Clear pointer after destroying
            }
        }
        free(blockchain->chain); // Free the array of Block* pointers
        blockchain->chain = NULL;
    }
    free(blockchain); // Free the Blockchain struct itself
    logger_log(LOG_LEVEL_INFO, "Blockchain destroyed.");
}
