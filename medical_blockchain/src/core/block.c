// src/core/block.c
#include "block.h"
#include "../crypto/sha256.h" // Include SHA256 for hashing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // For time()

/**
 * @brief Creates a new block.
 * @param index The index of the block.
 * @param previous_hash The hash of the previous block.
 * @param data The data to be stored in the block.
 * @param nonce The nonce for the block.
 * @return A pointer to the newly created Block structure, or NULL on failure.
 */
Block* block_create(uint32_t index, const char* previous_hash, const char* data, uint32_t nonce) {
    Block* new_block = (Block*)malloc(sizeof(Block));
    if (new_block == NULL) {
        perror("Failed to allocate memory for Block");
        return NULL;
    }

    new_block->index = index;
    new_block->timestamp = time(NULL); // Current time
    strncpy(new_block->previous_hash, previous_hash, MAX_PREVIOUS_HASH_LENGTH - 1);
    new_block->previous_hash[MAX_PREVIOUS_HASH_LENGTH - 1] = '\0'; // Ensure null-termination

    strncpy(new_block->data, data, MAX_DATA_LENGTH - 1);
    new_block->data[MAX_DATA_LENGTH - 1] = '\0'; // Ensure null-termination

    new_block->nonce = nonce;

    // Calculate the initial hash for the block
    block_calculate_hash(new_block, new_block->hash);

    return new_block;
}

/**
 * @brief Calculates the hash of a block.
 * The hash is calculated based on index, timestamp, previous_hash, data, and nonce.
 * @param block The block for which to calculate the hash.
 * @param output_hash A buffer to store the calculated hash (must be at least 65 bytes).
 */
void block_calculate_hash(const Block* block, char* output_hash) {
    if (block == NULL || output_hash == NULL) {
        fprintf(stderr, "Error: Invalid block or output_hash for hash calculation.\n");
        return;
    }

    // Concatenate relevant block data into a string for hashing
    // Make sure this buffer is large enough to hold all concatenated data
    char block_string[MAX_DATA_LENGTH + MAX_PREVIOUS_HASH_LENGTH + 128]; // Generous size
    snprintf(block_string, sizeof(block_string), "%u%ld%s%s%u",
             block->index,
             (long)block->timestamp, // Cast to long for snprintf
             block->previous_hash,
             block->data,
             block->nonce);

    sha256_hex_string(block_string, output_hash); // Use the SHA256 utility function
}

/**
 * @brief Prints the details of a block.
 * @param block The block to print.
 */
void block_print(const Block* block) {
    if (block == NULL) {
        printf("Block is NULL.\n");
        return;
    }
    printf("Block #%u\n", block->index);
    printf("  Timestamp: %ld\n", (long)block->timestamp);
    printf("  Previous Hash: %s\n", block->previous_hash);
    printf("  Hash: %s\n", block->hash);
    printf("  Data: %s\n", block->data);
    printf("  Nonce: %u\n", block->nonce);
}

/**
 * @brief Frees the memory allocated for a block.
 * @param block The block to free.
 */
void block_destroy(Block* block) {
    if (block != NULL) {
        // If 'data' or 'transactions' were dynamically allocated inside the Block struct,
        // they would need to be freed here. For now, they are fixed-size arrays.
        free(block);
    }
}
