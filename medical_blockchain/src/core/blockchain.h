// src/core/blockchain.h
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stddef.h> // For size_t
#include "block.h" // Assuming block.h will define the Block structure

// Define the Blockchain structure
typedef struct {
    Block* chain;      // Pointer to an array of blocks
    size_t length;     // Number of blocks in the chain
    // Add other blockchain-related fields here, e.g., difficulty, transactions pool
} Blockchain;

/**
 * @brief Initializes a new blockchain.
 * @return A pointer to the newly created Blockchain structure, or NULL on failure.
 */
Blockchain* blockchain_create();

/**
 * @brief Adds a new block to the blockchain.
 * @param blockchain The blockchain to add the block to.
 * @param new_block The block to be added.
 * @return 0 on success, -1 on failure.
 */
int blockchain_add_block(Blockchain* blockchain, Block* new_block);

/**
 * @brief Validates the entire blockchain.
 * @param blockchain The blockchain to validate.
 * @return 0 if valid, -1 if invalid.
 */
int blockchain_is_valid(const Blockchain* blockchain);

/**
 * @brief Frees the memory allocated for the blockchain.
 * @param blockchain The blockchain to free.
 */
void blockchain_destroy(Blockchain* blockchain);

#endif // BLOCKCHAIN_H
