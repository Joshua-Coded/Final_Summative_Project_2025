// src/core/blockchain.c
#include "blockchain.h"
#include "block.h" // For block-related functions/definitions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Initializes a new blockchain.
 * @return A pointer to the newly created Blockchain structure, or NULL on failure.
 */
Blockchain* blockchain_create() {
    Blockchain* bc = (Blockchain*)malloc(sizeof(Blockchain));
    if (bc == NULL) {
        perror("Failed to allocate memory for Blockchain");
        return NULL;
    }
    bc->chain = NULL; // Initially no blocks
    bc->length = 0;

    // Create the genesis block (the first block in the chain)
    Block* genesis_block = block_create(0, "0", "Genesis Block Data", 0); // Placeholder values
    if (genesis_block == NULL) {
        free(bc);
        return NULL;
    }

    if (blockchain_add_block(bc, genesis_block) != 0) {
        block_destroy(genesis_block);
        free(bc);
        return NULL;
    }

    printf("Blockchain created with genesis block.\n");
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
        fprintf(stderr, "Error: Blockchain or new_block is NULL.\n");
        return -1;
    }

    // Reallocate memory for the chain to add the new block
    Block* temp_chain = (Block*)realloc(blockchain->chain, (blockchain->length + 1) * sizeof(Block));
    if (temp_chain == NULL) {
        perror("Failed to reallocate memory for blockchain chain");
        return -1;
    }
    blockchain->chain = temp_chain;

    // Copy the new block into the chain
    // Note: This is a shallow copy if Block contains pointers. Deep copy might be needed.
    // For now, we assume Block struct copies directly.
    memcpy(&blockchain->chain[blockchain->length], new_block, sizeof(Block));
    blockchain->length++;

    printf("Block #%zu added to the blockchain.\n", new_block->index);
    return 0;
}

/**
 * @brief Validates the entire blockchain.
 * @param blockchain The blockchain to validate.
 * @return 0 if valid, -1 if invalid.
 */
int blockchain_is_valid(const Blockchain* blockchain) {
    if (blockchain == NULL || blockchain->length == 0) {
        return -1; // Invalid or empty blockchain
    }

    // The genesis block (index 0) has a previous hash of "0"
    if (strcmp(blockchain->chain[0].previous_hash, "0") != 0) {
        fprintf(stderr, "Invalid genesis block previous hash.\n");
        return -1;
    }

    for (size_t i = 1; i < blockchain->length; i++) {
        // Validate current block's hash
        char current_block_hash[65]; // SHA256 hash is 64 hex chars + null terminator
        block_calculate_hash(&blockchain->chain[i], current_block_hash);
        if (strcmp(blockchain->chain[i].hash, current_block_hash) != 0) {
            fprintf(stderr, "Block #%zu hash mismatch.\n", blockchain->chain[i].index);
            return -1;
        }

        // Validate previous hash linkage
        char prev_block_hash[65];
        block_calculate_hash(&blockchain->chain[i-1], prev_block_hash);
        if (strcmp(blockchain->chain[i].previous_hash, prev_block_hash) != 0) {
            fprintf(stderr, "Block #%zu previous hash mismatch.\n", blockchain->chain[i].index);
            return -1;
        }
        // TODO: Add Proof of Work validation here later
        // TODO: Add Merkle Root validation here later
    }
    printf("Blockchain is valid.\n");
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
    // Free each individual block if they were dynamically allocated inside the chain
    // For now, assuming blocks are copied and their internal data is handled by block_destroy if needed
    if (blockchain->chain != NULL) {
        for (size_t i = 0; i < blockchain->length; i++) {
            // If block_create allocates internal data, call block_destroy here for each.
            // For now, assuming Block struct is self-contained or simple fields.
            // If `Block` contains pointers to dynamically allocated data,
            // we'd need to call `block_destroy(&blockchain->chain[i]);`
            // Current `block_create` creates a simple struct, so `free(blockchain->chain)` is enough for the array.
        }
        free(blockchain->chain);
    }
    free(blockchain);
    printf("Blockchain destroyed.\n");
}
