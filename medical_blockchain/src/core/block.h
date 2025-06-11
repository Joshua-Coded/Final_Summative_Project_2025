// src/core/block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h> // For uint32_t, uint64_t
#include <time.h>   // For time_t

// Forward declaration for Transaction if needed, or include transaction.h
// #include "transaction.h"

#define MAX_PREVIOUS_HASH_LENGTH 65 // SHA256 hash (64 hex chars + null terminator)
#define MAX_HASH_LENGTH          65 // SHA256 hash (64 hex chars + null terminator)
#define MAX_DATA_LENGTH          2048 // Example max data length for a block

// Define the Block structure
typedef struct {
    uint32_t index;             // Block number
    time_t timestamp;           // Time of block creation
    char previous_hash[MAX_PREVIOUS_HASH_LENGTH]; // Hash of the previous block
    char hash[MAX_HASH_LENGTH];           // Hash of the current block
    char data[MAX_DATA_LENGTH];           // Medical record data (simplified for now)
    uint32_t nonce;             // Nonce for Proof of Work
    // char merkle_root[MAX_HASH_LENGTH]; // Merkle root of transactions (add later)
    // Transaction* transactions; // Array of transactions (add later)
    // size_t num_transactions; // Number of transactions
} Block;

/**
 * @brief Creates a new block.
 * @param index The index of the block.
 * @param previous_hash The hash of the previous block.
 * @param data The data to be stored in the block.
 * @param nonce The nonce for the block.
 * @return A pointer to the newly created Block structure, or NULL on failure.
 */
Block* block_create(uint32_t index, const char* previous_hash, const char* data, uint32_t nonce);

/**
 * @brief Calculates the hash of a block.
 * @param block The block for which to calculate the hash.
 * @param output_hash A buffer to store the calculated hash (must be at least 65 bytes).
 */
void block_calculate_hash(const Block* block, char* output_hash);

/**
 * @brief Prints the details of a block.
 * @param block The block to print.
 */
void block_print(const Block* block);

/**
 * @brief Frees the memory allocated for a block.
 * @param block The block to free.
 */
void block_destroy(Block* block);

#endif // BLOCK_H
