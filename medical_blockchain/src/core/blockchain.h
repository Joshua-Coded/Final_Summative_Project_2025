// src/core/blockchain.h
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t
#include "block.h" // For Block struct definition
#include "transaction.h" // For Transaction struct definition (needed for pending_transactions)

typedef struct Blockchain {
    Block** chain; // Dynamic array of Block pointers
    size_t capacity;
    size_t length;
    int difficulty; // Difficulty member for mining

    Transaction** pending_transactions;
    size_t num_pending_transactions;
    size_t pending_transactions_capacity;
} Blockchain;

Blockchain* blockchain_create();
int blockchain_add_block(Blockchain* blockchain, Block* new_block);
int blockchain_is_valid(const Blockchain* blockchain);
void blockchain_destroy(Blockchain* blockchain);
int blockchain_add_transaction_to_pending(Blockchain* blockchain, Transaction* tx);
int blockchain_mine_new_block(Blockchain* blockchain);
Block* blockchain_get_block_by_index(const Blockchain* blockchain, size_t index);
Block* blockchain_get_block_by_hash(const Blockchain* blockchain, const char* hash_hex); // Declared, needs definition
const Transaction* blockchain_get_transaction(const Blockchain* blockchain, const char* transaction_id); // Declared, needs definition

#endif // BLOCKCHAIN_H
