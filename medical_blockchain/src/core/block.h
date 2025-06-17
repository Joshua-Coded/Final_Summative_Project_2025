#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <time.h>
#include <stddef.h> // For size_t
#include "transaction.h"      // Make sure Transaction struct is defined here and is compatible
#include "../security/encryption.h" // Required for AES_256_KEY_SIZE
#include "../crypto/sha256.h" // Required for HASH_HEX_LEN if used for printing, and SHA256_DIGEST_LENGTH if BLOCK_HASH_SIZE uses it.

// Define the size of the block hash (SHA256)
#define BLOCK_HASH_SIZE 32 // This should consistently be SHA256_DIGEST_LENGTH from sha256.h

/**
 * @brief Represents a single block in the blockchain.
 * Each block contains metadata and a list of transactions.
 */
typedef struct Block {
    uint32_t index;              // The block's height in the blockchain
    int64_t timestamp;           // Time of block creation (Unix timestamp)
    uint8_t prev_hash[BLOCK_HASH_SIZE]; // Hash of the previous block
    uint8_t hash[BLOCK_HASH_SIZE];      // Hash of this block
    uint32_t nonce;              // Nonce value for Proof-of-Work
    size_t num_transactions;     // Number of transactions in this block
    // Dynamically allocated array of pointers to Transaction structs
    Transaction** transactions;
} Block;

// Function prototypes for block operations

/**
 * @brief Creates a new block.
 * @param index The index of the new block.
 * @param prev_hash The hash of the previous block.
 * @return A pointer to the newly created Block, or NULL on failure.
 * The caller is responsible for freeing the block and its transactions using block_destroy().
 */
Block* block_create(uint32_t index, const uint8_t prev_hash[BLOCK_HASH_SIZE]);

/**
 * @brief Adds a transaction to a block.
 * @param block A pointer to the block.
 * @param transaction A pointer to the transaction to add. The block takes ownership.
 * @return 0 on success, -1 on failure.
 */
int block_add_transaction(Block* block, Transaction* transaction);

/**
 * @brief Mines a block by finding a nonce that satisfies the difficulty target.
 * @param block A pointer to the block to mine.
 * @param difficulty The leading number of zero bits required in the block hash.
 * @return 0 on success, -1 on failure.
 */
int block_mine(Block* block, int difficulty);

/**
 * @brief Calculates the hash of a block.
 * This hash should include all block headers and transaction hashes.
 * @param block A pointer to the block.
 * @param output_hash A buffer to store the calculated hash (BLOCK_HASH_SIZE bytes).
 * @return 0 on success, -1 on failure.
 */
int block_calculate_hash(const Block* block, uint8_t output_hash[BLOCK_HASH_SIZE]);

/**
 * @brief Verifies the integrity of a block.
 * @param block A pointer to the block to verify.
 * @param difficulty The expected mining difficulty.
 * @return 0 if the block is valid, -1 otherwise.
 */
int block_is_valid(const Block* block, int difficulty);

/**
 * @brief Frees all memory allocated for a Block and its transactions.
 * @param block A pointer to the Block to destroy.
 */
void block_destroy(Block* block);

/**
 * @brief Prints the details of a block to the console.
 * @param block A pointer to the block to print.
 * @param encryption_key The key used for decryption, or NULL if not decrypting.
 */
void block_print(const Block* block, const uint8_t encryption_key[AES_256_KEY_SIZE]);

#endif // BLOCK_H
