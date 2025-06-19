// src/core/blockchain.c
#include "core/blockchain.h"
#include "core/block.h"
#include "core/transaction.h" // This now correctly provides TRANSACTION_ID_LEN
#include "utils/logger.h"
#include "utils/colors.h"
#include "crypto/hasher.h"
#include "mining/proof_of_work.h"
#include "config/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHAIN_INITIAL_CAPACITY 10

static const uint8_t GENESIS_PREV_HASH_BYTES[BLOCK_HASH_SIZE] = {0};

Blockchain* blockchain_create() {
    Blockchain* bc = (Blockchain*)malloc(sizeof(Blockchain));
    if (bc == NULL) {
        print_red("Failed to allocate memory for Blockchain\n");
        return NULL;
    }

    bc->chain = (Block**)malloc(sizeof(Block*) * CHAIN_INITIAL_CAPACITY);
    if (bc->chain == NULL) {
        print_red("Failed to allocate memory for blockchain chain (array of Block pointers)\n");
        free(bc);
        return NULL;
    }
    bc->capacity = CHAIN_INITIAL_CAPACITY;
    bc->length = 0;
    bc->difficulty = DEFAULT_DIFFICULTY;

    bc->pending_transactions = (Transaction**)malloc(sizeof(Transaction*) * PENDING_TRANSACTIONS_INITIAL_CAPACITY);
    if (bc->pending_transactions == NULL) {
        print_red("Failed to allocate memory for pending transactions\n");
        free(bc->chain);
        free(bc);
        return NULL;
    }
    bc->pending_transactions_capacity = PENDING_TRANSACTIONS_INITIAL_CAPACITY;
    bc->num_pending_transactions = 0;

    Block* genesis_block = block_create(0, GENESIS_PREV_HASH_BYTES);
    if (genesis_block == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create genesis block.");
        free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Mining Genesis Block (Block #0) with difficulty %d...", DEFAULT_DIFFICULTY);
    if (block_mine(genesis_block, DEFAULT_DIFFICULTY) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to mine genesis block.");
        block_destroy(genesis_block);
        free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        return NULL;
    }

    if (blockchain_add_block(bc, genesis_block) != 0) {
        block_destroy(genesis_block);
        free(bc->pending_transactions);
        free(bc->chain);
        free(bc);
        logger_log(LOG_LEVEL_FATAL, "Failed to add genesis block to blockchain.");
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Blockchain created with genesis block (Difficulty: %d).", bc->difficulty);
    print_green("Genesis Block (Block #0) created and mined successfully!\n");
    return bc;
}

int blockchain_add_block(Blockchain* blockchain, Block* new_block) {
    if (blockchain == NULL || new_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain or new_block is NULL in blockchain_add_block.");
        return -1;
    }

    if (blockchain->length == blockchain->capacity) {
        size_t new_capacity = blockchain->capacity * 2;
        if (new_capacity == 0) new_capacity = CHAIN_INITIAL_CAPACITY;

        Block** temp_chain = (Block**)realloc(blockchain->chain, new_capacity * sizeof(Block*));
        if (temp_chain == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for blockchain chain.");
            print_red("Failed to reallocate memory for blockchain chain.\n");
            return -1;
        }
        blockchain->chain = temp_chain;
        blockchain->capacity = new_capacity;
        logger_log(LOG_LEVEL_DEBUG, "Blockchain capacity increased to %zu.", new_capacity);
    }

    blockchain->chain[blockchain->length] = new_block;
    blockchain->length++;

    logger_log(LOG_LEVEL_INFO, "Block #%u added to the blockchain. Current length: %zu.",
               new_block->index, blockchain->length);
    print_green("Block #%u added to the blockchain. ", new_block->index);
    printf("Current length: ");
    print_yellow("%zu\n", blockchain->length);
    return 0;
}

int blockchain_add_transaction_to_pending(Blockchain* blockchain, Transaction* tx) {
    if (blockchain == NULL || tx == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain or transaction is NULL when adding to pending list.");
        return -1;
    }

    if (blockchain->num_pending_transactions == blockchain->pending_transactions_capacity) {
        size_t new_capacity = blockchain->pending_transactions_capacity * 2;
        if (new_capacity == 0) new_capacity = PENDING_TRANSACTIONS_INITIAL_CAPACITY;

        Transaction** temp_tx = (Transaction**)realloc(blockchain->pending_transactions, new_capacity * sizeof(Transaction*));
        if (temp_tx == NULL) {
            logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for pending transactions.");
            print_red("Failed to reallocate memory for pending transactions.\n");
            return -1;
        }
        blockchain->pending_transactions = temp_tx;
        blockchain->pending_transactions_capacity = new_capacity;
        logger_log(LOG_LEVEL_DEBUG, "Pending transactions capacity increased to %zu.", new_capacity);
    }

    blockchain->pending_transactions[blockchain->num_pending_transactions] = tx;
    blockchain->num_pending_transactions++;
    logger_log(LOG_LEVEL_INFO, "Transaction added to pending list. Total pending: %zu.", blockchain->num_pending_transactions);
    print_green("Transaction added to pending list. ");
    printf("Total pending: ");
    print_yellow("%zu\n", blockchain->num_pending_transactions);
    return 0;
}

int blockchain_mine_new_block(Blockchain* blockchain) {
    if (blockchain == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Blockchain is NULL when mining a new block.");
        return -1;
    }

    Block* last_block = blockchain->chain[blockchain->length - 1];
    if (last_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Last block is NULL, cannot mine a new block.");
        print_red("Error: Last block is NULL, cannot mine a new block.\n");
        return -1;
    }

    Block* new_block = block_create(last_block->index + 1, last_block->hash);
    if (new_block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new block for mining.");
        print_red("Failed to create new block for mining.\n");
        return -1;
    }

    for (size_t i = 0; i < blockchain->num_pending_transactions; ++i) {
        if (blockchain->pending_transactions[i] != NULL) {
            if (block_add_transaction(new_block, blockchain->pending_transactions[i]) != 0) {
                logger_log(LOG_LEVEL_WARN, "Failed to add pending transaction %zu to new block. Continuing with others.", i);
                print_yellow("Warning: Failed to add pending transaction %zu to new block. Continuing.\n", i);
            } else {
                blockchain->pending_transactions[i] = NULL; // Mark as moved to the block
            }
        }
    }

    logger_log(LOG_LEVEL_INFO, "Attempting to mine new block #%u with %zu transactions...",
               new_block->index, new_block->num_transactions);
    print_cyan("Attempting to mine new block #%u with %zu transactions...\n",
               new_block->index, new_block->num_transactions);

    if (block_mine(new_block, blockchain->difficulty) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to mine new block.");
        print_red("Failed to mine new block.\n");
        block_destroy(new_block);
        return -1;
    }

    if (blockchain_add_block(blockchain, new_block) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to add mined block to the blockchain.");
        print_red("Failed to add mined block to the blockchain.\n");
        block_destroy(new_block);
        return -1;
    }

    // Free transactions that were added to the block and clear pending list
    // Note: It's important to ensure block_add_transaction creates a copy,
    // or else transactions should only be destroyed here if they are truly "consumed".
    // If block_add_transaction just takes a pointer, we shouldn't destroy here.
    // Assuming block_add_transaction copies the transaction, this is correct.
    for (size_t i = 0; i < blockchain->num_pending_transactions; ++i) {
        if (blockchain->pending_transactions[i] != NULL) {
            transaction_destroy(blockchain->pending_transactions[i]);
        }
    }
    blockchain->num_pending_transactions = 0;
    logger_log(LOG_LEVEL_INFO, "Pending transactions cleared after mining block #%u.", new_block->index);
    print_green("Pending transactions cleared after mining block #%u.\n", new_block->index);

    return 0;
}

Block* blockchain_get_block_by_index(const Blockchain* blockchain, size_t index) {
    if (blockchain == NULL || index >= blockchain->length) {
        logger_log(LOG_LEVEL_ERROR, "Error: Invalid blockchain or index %zu (length %zu) in blockchain_get_block_by_index.",
                   index, blockchain ? blockchain->length : 0);
        return NULL;
    }
    return blockchain->chain[index];
}

Block* blockchain_get_block_by_hash(const Blockchain* blockchain, const char* hash_hex) {
    if (blockchain == NULL || hash_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Invalid blockchain or hash_hex is NULL in blockchain_get_block_by_hash.");
        return NULL;
    }

    uint8_t target_hash_bytes[BLOCK_HASH_SIZE];
    if (hasher_hex_to_bytes_buf(hash_hex, target_hash_bytes, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid hash hex string provided for lookup in blockchain_get_block_by_hash.");
        return NULL;
    }

    for (size_t i = 0; i < blockchain->length; ++i) {
        // Ensure the stored block hash is also in bytes for memcmp
        if (memcmp(blockchain->chain[i]->hash, target_hash_bytes, BLOCK_HASH_SIZE) == 0) {
            return blockchain->chain[i];
        }
    }

    logger_log(LOG_LEVEL_INFO, "Block with hash %s not found.", hash_hex);
    return NULL;
}

const Transaction* blockchain_get_transaction(const Blockchain* blockchain, const char* transaction_id_hex) {
    if (blockchain == NULL || transaction_id_hex == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error: Invalid blockchain or transaction_id_hex is NULL in blockchain_get_transaction.");
        return NULL;
    }

    // The transaction ID in the struct is already a hex string (char array)
    // We can directly compare it with the provided transaction_id_hex
    for (size_t i = 0; i < blockchain->length; ++i) {
        Block* current_block = blockchain->chain[i];
        for (size_t j = 0; j < current_block->num_transactions; ++j) {
            const Transaction* tx = current_block->transactions[j];
            // Compare the transaction_id string directly
            if (strcmp(tx->transaction_id, transaction_id_hex) == 0) {
                return tx;
            }
        }
    }

    logger_log(LOG_LEVEL_INFO, "Transaction with ID %s not found.", transaction_id_hex);
    return NULL;
}

int blockchain_is_valid(const Blockchain* blockchain) {
    if (blockchain == NULL || blockchain->length == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid or empty blockchain provided for validation.");
        print_red("Invalid or empty blockchain provided for validation.\n");
        return -1;
    }

    uint8_t calculated_hash[BLOCK_HASH_SIZE];

    print_cyan("Starting blockchain validation...\n");

    // Validate Genesis Block
    if (memcmp(blockchain->chain[0]->prev_hash, GENESIS_PREV_HASH_BYTES, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid genesis block previous hash. Expected all zeros, Got %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->prev_hash, BLOCK_HASH_SIZE));
        print_red("Validation Failed: Genesis block has incorrect previous hash.\n");
        return -1;
    }

    if (block_calculate_hash(blockchain->chain[0], calculated_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for genesis block validation.");
        print_red("Validation Failed: Failed to calculate hash for Genesis Block.\n");
        return -1;
    }

    if (memcmp(blockchain->chain[0]->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block hash mismatch. Stored: %s, Recalculated: %s.",
                   hasher_bytes_to_hex(blockchain->chain[0]->hash, BLOCK_HASH_SIZE),
                   hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
        print_red("Validation Failed: Genesis block hash mismatch.\n");
        return -1;
    }

    if (block_is_valid(blockchain->chain[0], blockchain->difficulty) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Genesis block is invalid (failed block_is_valid check).");
        print_red("Validation Failed: Genesis block failed internal validation (PoW or transactions).\n");
        return -1;
    }
    print_green("Genesis Block (#0) validated successfully.\n");

    // Validate subsequent blocks
    for (size_t i = 1; i < blockchain->length; i++) {
        Block* current_block = blockchain->chain[i];
        Block* prev_block = blockchain->chain[i-1];

        print_cyan("  Validating Block #%u...\n", current_block->index);

        if (current_block->index != prev_block->index + 1) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u has invalid index. Expected %u, Got %u.",
                       current_block->index, prev_block->index + 1, current_block->index);
            print_red("Validation Failed: Block #%u has invalid index.\n", current_block->index);
            return -1;
        }

        if (block_calculate_hash(current_block, calculated_hash) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for block #%u validation.", current_block->index);
            print_red("Validation Failed: Failed to calculate hash for Block #%u.\n", current_block->index);
            return -1;
        }

        if (memcmp(current_block->hash, calculated_hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u hash mismatch. Stored: %s, Recalculated: %s.",
                       current_block->index,
                       hasher_bytes_to_hex(current_block->hash, BLOCK_HASH_SIZE),
                       hasher_bytes_to_hex(calculated_hash, BLOCK_HASH_SIZE));
            print_red("Validation Failed: Block #%u hash mismatch.\n", current_block->index);
            return -1;
        }

        if (memcmp(current_block->prev_hash, prev_block->hash, BLOCK_HASH_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u previous hash mismatch. Expected %s (from block %u), Got %s.",
                       current_block->index,
                       hasher_bytes_to_hex(prev_block->hash, BLOCK_HASH_SIZE),
                       prev_block->index,
                       hasher_bytes_to_hex(current_block->prev_hash, BLOCK_HASH_SIZE));
            print_red("Validation Failed: Block #%u previous hash does not match Block #%u's hash.\n",
                      current_block->index, prev_block->index);
            return -1;
        }

        if (block_is_valid(current_block, blockchain->difficulty) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Block #%u is invalid (failed block_is_valid check).", current_block->index);
            print_red("Validation Failed: Block #%u is invalid (failed internal validation).\n", current_block->index);
            return -1;
        }
        print_green("  Block #%u validated successfully.\n", current_block->index);
    }

    print_green("Blockchain is valid.\n");
    return 0;
}

void blockchain_destroy(Blockchain* blockchain) {
    if (blockchain == NULL) {
        return;
    }

    print_cyan("Destroying blockchain...\n");

    if (blockchain->chain != NULL) {
        for (size_t i = 0; i < blockchain->length; i++) {
            if (blockchain->chain[i] != NULL) {
                block_destroy(blockchain->chain[i]);
            }
        }
        free(blockchain->chain);
        blockchain->chain = NULL;
    }

    if (blockchain->pending_transactions != NULL) {
        for (size_t i = 0; i < blockchain->num_pending_transactions; i++) {
            if (blockchain->pending_transactions[i] != NULL) {
                transaction_destroy(blockchain->pending_transactions[i]);
            }
        }
        free(blockchain->pending_transactions);
        blockchain->pending_transactions = NULL;
    }

    free(blockchain);
    print_cyan("Blockchain destroyed.\n");
}
