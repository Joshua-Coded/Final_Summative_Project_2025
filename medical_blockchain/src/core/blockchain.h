// src/core/blockchain.h
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t
#include "block.h" // For Block struct definition

typedef struct Blockchain {
    Block** chain;    // <-- CRITICAL CHANGE: from Block* to Block**
    size_t capacity;
    size_t length;
    // Add other blockchain-specific fields like difficulty if necessary
} Blockchain;

// Function prototypes
Blockchain* blockchain_create();
int blockchain_add_block(Blockchain* blockchain, Block* new_block);
int blockchain_is_valid(const Blockchain* blockchain);
void blockchain_destroy(Blockchain* blockchain);

#endif // BLOCKCHAIN_H
