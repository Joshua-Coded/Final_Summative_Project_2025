// src/core/block.c
#include "block.h"
#include "transaction.h"      // For Transaction struct, transaction_destroy, and transaction_is_valid
#include "../crypto/hasher.h" // For hasher_sha256, hasher_bytes_to_hex, SHA256_HASH_SIZE, HASH_HEX_LEN
// ^^^ hasher.h now includes sha256.h, so SHA256_HASH_SIZE and HASH_HEX_LEN are available

#include "../security/encryption.h" // Required for encryption/decryption functions and AES_256_KEY_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE
#include "../utils/logger.h"
#include "../utils/colors.h" // Include colors header
#include "../config/config.h" // For BLOCKCHAIN_DIFFICULTY, MAX_TRANSACTIONS_PER_BLOCK, BLOCK_HASH_SIZE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>           // For snprintf, printf
#include <time.h>            // For time(), ctime()
#include <limits.h>          // For UINT32_MAX

/**
 * @brief Creates a new block.
 * @param index The index of the new block.
 * @param prev_hash The hash of the previous block (binary).
 * @return A pointer to the newly created Block, or NULL on failure.
 * The caller is responsible for freeing the block and its transactions using block_destroy().
 */
Block* block_create(uint32_t index, const uint8_t prev_hash[BLOCK_HASH_SIZE]) {
    Block* block = (Block*)calloc(1, sizeof(Block)); // Use calloc to zero-initialize
    if (block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for a new block.");
        return NULL;
    }

    block->index = index;
    block->timestamp = time(NULL); // Current Unix timestamp
    memcpy(block->prev_hash, prev_hash, BLOCK_HASH_SIZE); // Copy raw hash bytes
    memset(block->hash, 0, BLOCK_HASH_SIZE); // Initialize block hash to zeros
    block->nonce = 0;
    block->num_transactions = 0;
    block->transactions = NULL; // Initialize transactions array pointer

    logger_log(LOG_LEVEL_DEBUG, "Block #%u created.", block->index);
    return block;
}

/**
 * @brief Adds a transaction to a block.
 * Dynamically resizes the transactions array as needed.
 * @param block A pointer to the block.
 * @param transaction A pointer to the transaction to add. The block takes ownership.
 * @return 0 on success, -1 on failure.
 */
int block_add_transaction(Block* block, Transaction* transaction) {
    if (block == NULL || transaction == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot add transaction: Block or transaction is NULL.");
        return -1;
    }

    // Allocate or reallocate memory for the array of Transaction pointers
    Transaction** temp_transactions = (Transaction**)realloc(block->transactions,
                                                             (block->num_transactions + 1) * sizeof(Transaction*));
    if (temp_transactions == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to reallocate memory for transactions in Block #%u.", block->index);
        return -1;
    }

    block->transactions = temp_transactions;
    block->transactions[block->num_transactions] = transaction; // Store the pointer
    block->num_transactions++;

    // Removed: char tx_id_hex[HASH_HEX_LEN + 1]; // This variable is no longer needed
    logger_log(LOG_LEVEL_DEBUG, "Transaction %s added to Block #%u.", transaction->transaction_id, block->index);
    return 0;
}

/**
 * @brief Mines a block by finding a nonce that satisfies the difficulty target.
 * @param block A pointer to the block to mine.
 * @param difficulty The leading number of zero characters required in the block hash (hex representation).
 * @return 0 on success, -1 on failure.
 */
int block_mine(Block* block, int difficulty) {
    if (block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot mine a NULL block.");
        return -1;
    }

    uint8_t calculated_hash[BLOCK_HASH_SIZE]; // Buffer to store the calculated hash

    // Construct the target prefix string (e.g., "00" for difficulty 2)
    char target_str[difficulty + 1];
    for (int i = 0; i < difficulty; i++) {
        target_str[i] = '0';
    }
    target_str[difficulty] = '\0';

    logger_log(LOG_LEVEL_INFO, "Mining Block #%u with difficulty %d (target prefix: '%s').", block->index, difficulty, target_str);

    block->nonce = 0; // Start nonce from 0
    while (1) {
        if (block_calculate_hash(block, calculated_hash) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash during mining for Block #%u.", block->index);
            return -1;
        }

        // Convert calculated_hash (binary) to hex string for comparison
        char hash_hex[HASH_HEX_LEN + 1]; // Use HASH_HEX_LEN from hasher.h
        hasher_bytes_to_hex_buf(calculated_hash, BLOCK_HASH_SIZE, hash_hex, sizeof(hash_hex)); // Fixed buf_len

        // Check if the hash meets the difficulty requirement (leading zeros in hex)
        if (strncmp(hash_hex, target_str, difficulty) == 0) {
            memcpy(block->hash, calculated_hash, BLOCK_HASH_SIZE); // Copy the winning binary hash
            logger_log(LOG_LEVEL_INFO, "Block #%u mined successfully! Nonce: %u, Hash: %s", block->index, block->nonce, hash_hex);
            return 0; // Success
        }

        block->nonce++;
        if (block->nonce == UINT32_MAX) { // Prevent infinite loop in case solution is not found
            logger_log(LOG_LEVEL_ERROR, "Nonce reached max value, unable to mine block %u with current difficulty.", block->index);
            return -1;
        }
    }
}

/**
 * @brief Calculates the hash of a block.
 * This hash includes: index, timestamp, nonce, previous hash, and all transaction IDs.
 * All these components are concatenated into a single binary buffer for SHA256 hashing.
 * @param block A pointer to the block.
 * @param output_hash A buffer to store the calculated hash (BLOCK_HASH_SIZE bytes).
 * @return 0 on success, -1 on failure.
 */
int block_calculate_hash(const Block* block, uint8_t output_hash[BLOCK_HASH_SIZE]) {
    if (block == NULL || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot calculate hash: Block or output_hash is NULL.");
        return -1;
    }

    // --- Step 1: Determine the total size needed for the data to be hashed ---
    // The data includes:
    // 1. Block index (as string)
    // 2. Timestamp (as string)
    // 3. Nonce (as string)
    // 4. Previous block hash (binary, BLOCK_HASH_SIZE bytes)
    // 5. Concatenated binary transaction IDs (each SHA256_HASH_SIZE bytes)
    //    NOTE: If transaction_id is a HEX string in Transaction struct, it needs to be converted back to binary first,
    //    or simply include the hex string directly in the hash input if that's the design.
    //    Given the error message, 'transaction_id' is already a char array for hex.
    //    For hashing, it's often best to hash the raw binary if possible, but if the ID is defined as the hex string,
    //    you can hash the hex string representation. Let's assume for now you hash the hex string for simplicity
    //    as that aligns with the struct definition. If you intended to hash the RAW transaction hash,
    //    your Transaction struct would need a uint8_t transaction_id[SHA256_HASH_SIZE] member.

    char header_numeric_str[256]; // Buffer for index, timestamp, nonce as strings
    // Using %u for uint32_t (index, nonce) and %lld for time_t (timestamp), which is usually long long
    int header_len = snprintf(header_numeric_str, sizeof(header_numeric_str),
                              "%u%lld%u",
                              block->index,
                              (long long)block->timestamp, // Explicit cast for %lld
                              block->nonce);

    if (header_len < 0 || (size_t)header_len >= sizeof(header_numeric_str)) {
        logger_log(LOG_LEVEL_ERROR, "Failed to format block header string for hashing (snprintf error/truncation).");
        return -1;
    }

    size_t total_data_len = header_len;
    total_data_len += BLOCK_HASH_SIZE; // For prev_hash (binary)

    // Add length for all transaction IDs (hex string length)
    // Each transaction ID is TRANSACTION_ID_LEN bytes (SHA256_HEX_LEN)
    for (size_t i = 0; i < block->num_transactions; i++) {
        if (block->transactions[i] == NULL) {
            logger_log(LOG_LEVEL_ERROR, "NULL transaction found in Block #%u at index %zu during hash calculation.", block->index, i);
            return -1;
        }
        total_data_len += TRANSACTION_ID_LEN; // Each transaction ID is a hex string (TRANSACTION_ID_LEN chars)
    }

    // --- Step 2: Allocate memory and concatenate all data into a single uint8_t buffer ---
    // Note: We are concatenating strings and binary data. For SHA256, it's generally best to hash raw bytes.
    // If transaction_id is a hex string, it means it's 64 characters. Hashing that string directly is fine,
    // but typically a block hash would include the *raw binary hash* of its transactions.
    // For now, I'll assume you intend to hash the hex string of transaction IDs as per your struct.
    uint8_t* data_to_hash_buffer = (uint8_t*)malloc(total_data_len);
    if (data_to_hash_buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for block data to hash.");
        return -1;
    }

    size_t current_offset = 0;

    // Copy header numeric string (index, timestamp, nonce)
    memcpy(data_to_hash_buffer + current_offset, header_numeric_str, header_len);
    current_offset += header_len;

    // Append previous hash (binary)
    memcpy(data_to_hash_buffer + current_offset, block->prev_hash, BLOCK_HASH_SIZE);
    current_offset += BLOCK_HASH_SIZE;

    // Append all transaction IDs (hex string)
    for (size_t i = 0; i < block->num_transactions; i++) {
        // block->transactions[i]->transaction_id is char[TRANSACTION_ID_LEN + 1] (hex string)
        memcpy(data_to_hash_buffer + current_offset, block->transactions[i]->transaction_id, TRANSACTION_ID_LEN);
        current_offset += TRANSACTION_ID_LEN;
    }

    // --- Step 3: Perform SHA256 hashing ---
    hasher_sha256(data_to_hash_buffer, current_offset, output_hash); // Call hasher_sha256 directly (void return)
    free(data_to_hash_buffer); // Free the temporary buffer

    return 0;
}

/**
 * @brief Verifies the integrity of a block.
 * @param block A pointer to the block to verify.
 * @param difficulty The expected mining difficulty.
 * @return 0 if the block is valid, -1 otherwise.
 */
int block_is_valid(const Block* block, int difficulty) {
    if (block == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot validate a NULL block.");
        return -1;
    }

    uint8_t calculated_hash[BLOCK_HASH_SIZE];
    if (block_calculate_hash(block, calculated_hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for validation of Block #%u.", block->index);
        return -1;
    }

    // Compare calculated hash with stored hash
    if (memcmp(calculated_hash, block->hash, BLOCK_HASH_SIZE) != 0) {
        // Note: hasher_bytes_to_hex returns a dynamically allocated string,
        // so these calls create memory leaks if not freed.
        // For debugging/logging, often acceptable, but ideally use _buf version.
        char stored_hash_hex[HASH_HEX_LEN + 1];
        char calculated_hash_hex[HASH_HEX_LEN + 1];
        hasher_bytes_to_hex_buf(block->hash, BLOCK_HASH_SIZE, stored_hash_hex, sizeof(stored_hash_hex));
        hasher_bytes_to_hex_buf(calculated_hash, BLOCK_HASH_SIZE, calculated_hash_hex, sizeof(calculated_hash_hex));

        logger_log(LOG_LEVEL_WARN, "Block #%u hash mismatch. Stored: %s, Calculated: %s",
                                   block->index,
                                   stored_hash_hex,
                                   calculated_hash_hex);
        return -1;
    }

    // Check difficulty proof (leading zeros in hex representation)
    char hash_hex[HASH_HEX_LEN + 1]; // Use HASH_HEX_LEN
    hasher_bytes_to_hex_buf(block->hash, BLOCK_HASH_SIZE, hash_hex, sizeof(hash_hex)); // Fixed buf_len

    for (int i = 0; i < difficulty; i++) {
        if (hash_hex[i] != '0') {
            logger_log(LOG_LEVEL_WARN, "Block #%u does not meet difficulty target. Hash: %s", block->index, hash_hex);
            return -1;
        }
    }

    // Verify all transactions within the block
    for (size_t i = 0; i < block->num_transactions; i++) {
        if (block->transactions[i] == NULL || transaction_is_valid(block->transactions[i]) != 0) {
            char tx_id_hex[HASH_HEX_LEN + 1]; // This is used here, so keep it!
            if (block->transactions[i] != NULL) {
                // transaction->transaction_id is already hex string, so just copy it
                snprintf(tx_id_hex, sizeof(tx_id_hex), "%s", block->transactions[i]->transaction_id);
                logger_log(LOG_LEVEL_WARN, "Invalid transaction %s found in Block #%u at index %zu.", tx_id_hex, block->index, i);
            } else {
                logger_log(LOG_LEVEL_WARN, "NULL transaction pointer found in Block #%u at index %zu.", block->index, i);
            }
            return -1;
        }
    }

    logger_log(LOG_LEVEL_DEBUG, "Block #%u is valid.", block->index);
    return 0;
}


/**
 * @brief Frees all memory allocated for a Block and its transactions.
 * @param block A pointer to the Block to destroy.
 */
void block_destroy(Block* block) {
    if (block == NULL) {
        return;
    }

    logger_log(LOG_LEVEL_DEBUG, "Destroying Block #%u.", block->index);

    if (block->transactions != NULL) {
        for (size_t i = 0; i < block->num_transactions; i++) {
            if (block->transactions[i] != NULL) {
                // The transaction_destroy function should handle freeing
                // encrypted_medical_data within the Transaction struct.
                transaction_destroy(block->transactions[i]); // Correct call
            }
        }
        free(block->transactions); // Free the array of Transaction pointers
        block->transactions = NULL;
    }

    free(block); // Free the Block struct itself
    logger_log(LOG_LEVEL_DEBUG, "Block destroyed.");
}

/**
 * @brief Prints the details of a block to the console.
 * @param block A pointer to the block to print.
 * @param encryption_key The key used for decryption, or NULL if not decrypting.
 */
void block_print(const Block* block, const uint8_t encryption_key[AES_256_KEY_SIZE]) {
    if (block == NULL) {
        print_red("Block is NULL.\n"); // Use helper function
        return;
    }

    char hash_hex[HASH_HEX_LEN + 1];
    char prev_hash_hex[HASH_HEX_LEN + 1];

    hasher_bytes_to_hex_buf(block->hash, BLOCK_HASH_SIZE, hash_hex, sizeof(hash_hex));
    hasher_bytes_to_hex_buf(block->prev_hash, BLOCK_HASH_SIZE, prev_hash_hex, sizeof(prev_hash_hex));

    print_bold_cyan("--- Block #%u ---\n", block->index); // Use print_bold_cyan
    print_yellow("  Timestamp:     ");
    printf("%lld (", (long long)block->timestamp);
    print_bright_black("%s", ctime((const time_t *)&block->timestamp));
    printf(")\n");
    print_yellow("  Prev Hash:     ");
    printf("%s\n", prev_hash_hex);
    print_yellow("  Hash:          ");
    printf("%s\n", hash_hex);
    print_yellow("  Nonce:         ");
    printf("%u\n", block->nonce);
    print_yellow("  Transactions: ");
    printf("%zu\n", block->num_transactions);

    if (block->num_transactions > 0 && block->transactions != NULL) {
        print_magenta("  --- Transactions in Block #%u ---\n", block->index);
        for (size_t i = 0; i < block->num_transactions; i++) {
            print_blue("  Tx %zu:\n", i);
            Transaction* tx = block->transactions[i];
            if (tx == NULL) {
                print_red("    Tx %zu: (NULL)\n", i);
                continue;
            }
            transaction_print(tx, encryption_key); // Corrected function call
        }
    } else {
        print_yellow("  No transactions in this block.\n");
    }
    print_bold_cyan("--------------------------------------------------\n\n");
}
