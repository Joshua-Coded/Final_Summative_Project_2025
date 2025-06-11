// src/core/block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <time.h>
#include "config/blockchain_config.h" // For MAX_TRANSACTIONS_PER_BLOCK, etc.
#include "core/transaction.h" // Include transaction header

// Block structure definition
typedef struct {
    unsigned int index;
    char hash[SHA256_HEX_LEN + 1];           // Hex string representation of current block's hash
    char prev_hash[SHA256_HEX_LEN + 1];      // Hex string representation of previous block's hash
    time_t timestamp;
    unsigned int nonce;
    // Add transactions to the block
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK];
    unsigned int num_transactions; // Number of transactions currently in the block
} Block;

// Function declarations
Block* block_create(unsigned int index, const char* prev_hash, unsigned int nonce,
                    Transaction* transactions, unsigned int num_transactions); // UPDATED SIGNATURE
void block_destroy(Block* block);
void block_calculate_hash(Block* block);
void block_print(const Block* block);
int block_add_transaction(Block* block, const Transaction* transaction); // New function to add transactions

#endif // BLOCK_H
