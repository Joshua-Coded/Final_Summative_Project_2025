// src/core/block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h> // For size_t
#include <stdint.h> // For uint8_t
#include <time.h>   // For time_t
#include "transaction.h" // Include Transaction struct definition
#include "../../config/blockchain_config.h" // For HASH_LENGTH, etc.

// Forward declaration for SHA256_HEX_LEN if not already defined via blockchain_config.h
// If your config.h doesn't define it, you might need to include hasher.h here for SHA256_HEX_LEN
// or define it in config.h. Assuming it's available.
#ifndef SHA256_HEX_LEN
#define SHA256_HEX_LEN 64 // 256 bits = 32 bytes, hex is 2 chars per byte (64)
#endif


// --- Block Structure ---
typedef struct Block {
    unsigned int index;
    time_t timestamp;
    char prev_hash[SHA256_HEX_LEN + 1]; // Hex string representation of previous block's hash
    char hash[SHA256_HEX_LEN + 1];      // Hex string representation of this block's hash
    unsigned int nonce;                 // Nonce for Proof-of-Work
    Transaction** transactions;         // Dynamic array of pointers to transactions
    size_t num_transactions;            // Number of transactions in the block
} Block;

/**
 * @brief Creates a new block.
 * @param index The index of the block in the blockchain.
 * @param prev_hash The hash of the previous block.
 * @param nonce The nonce for the Proof-of-Work.
 * @return A pointer to the newly created Block on success, NULL on failure.
 * The caller is responsible for freeing the block using block_destroy.
 */
Block* block_create(unsigned int index, const char* prev_hash, unsigned int nonce);

/**
 * @brief Destroys a block and frees all its allocated memory, including transactions.
 * @param block A pointer to the Block to destroy.
 */
void block_destroy(Block* block);

/**
 * @brief Adds a transaction to a block.
 * @param block A pointer to the Block to which the transaction will be added.
 * @param transaction A pointer to the Transaction to add.
 * @return 0 on success, -1 on failure.
 */
int block_add_transaction(Block* block, Transaction* transaction);

/**
 * @brief Prints the details of a block.
 * @param block A pointer to the Block to print.
 */
void block_print(const Block* block);

/**
 * @brief Prints the details of a block, attempting to decrypt medical data.
 * @param block A pointer to the Block to print.
 * @param encryption_key The AES encryption key (32 bytes for AES-256) for decrypting medical data, or NULL if not available.
 */
void block_print_with_decryption(const Block* block, const uint8_t encryption_key[AES_256_KEY_SIZE]);


/**
 * @brief Calculates the SHA256 hash of a block.
 * The hash includes all block metadata and a merkle root of transactions (simplified here).
 * @param block A pointer to the Block.
 * @param output_hash A buffer to store the resulting SHA256 hash (SHA256_HEX_LEN + 1 bytes).
 * @return 0 on success, -1 on failure.
 */
int block_calculate_hash(const Block* block, char* output_hash);


#endif // BLOCK_H
