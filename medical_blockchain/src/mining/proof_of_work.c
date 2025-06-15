// src/mining/proof_of_work.c
#include "proof_of_work.h"
#include "../core/block.h"
#include "../crypto/hasher.h" // <--- Use hasher.h for HASH_HEX_LEN and SHA256_HASH_SIZE
#include "../utils/logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/**
 * @brief Mines a block to find a hash that meets the proof-of-work difficulty.
 * The hash must start with 'difficulty' number of zeros (in its hexadecimal representation).
 * @param block A pointer to the Block to be mined.
 * @param difficulty The number of leading zeros required in the block hash.
 * @return 0 on success (block mined), -1 on failure.
 */
int proof_of_work_mine_block(Block* block, int difficulty) {
    if (block == NULL || difficulty < 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for proof_of_work_mine_block.");
        return -1;
    }

    char target_prefix[HASH_HEX_LEN + 1]; // e.g., "00" for difficulty 2
    for (int i = 0; i < difficulty; i++) {
        target_prefix[i] = '0';
    }
    target_prefix[difficulty] = '\0';

    logger_log(LOG_LEVEL_DEBUG, "Starting mining for block %u with difficulty %d (target prefix: '%s')...", block->index, difficulty, target_prefix);

    // Reset nonce to 0 before starting to mine
    block->nonce = 0;

    // This will hold the 32-byte RAW hash
    uint8_t raw_block_hash[SHA256_HASH_SIZE]; // Use SHA256_HASH_SIZE from hasher.h
    // This will hold the 64-character HEX string representation of the hash
    char hex_block_hash_str[HASH_HEX_LEN + 1];

    int attempts = 0;

    while (1) {
        // Calculate the raw 32-byte hash
        block_calculate_hash(block, raw_block_hash);

        // Convert the raw hash to its hexadecimal string representation using hasher_bytes_to_hex_buf
        hasher_bytes_to_hex_buf(raw_block_hash, SHA256_HASH_SIZE, hex_block_hash_str, sizeof(hex_block_hash_str));

        attempts++;

        // Check if the hexadecimal hash meets the difficulty target
        if (strncmp(hex_block_hash_str, target_prefix, difficulty) == 0) {
            logger_log(LOG_LEVEL_INFO, "Block #%u mined! Nonce: %u, Hash: %s, Attempts: %d",
                         block->index, block->nonce, hex_block_hash_str, attempts);

            // Copy the raw 32-byte hash into the block's hash field
            memcpy(block->hash, raw_block_hash, SHA256_HASH_SIZE);
            
            return 0; // Success
        }

        block->nonce++;

        // Optional: Log progress every million attempts
        if (attempts % 1000000 == 0) {
            logger_log(LOG_LEVEL_DEBUG, "Block #%u: Attempt %d, Current Nonce: %u, Current Hash: %s",
                         block->index, attempts, block->nonce, hex_block_hash_str);
        }
    }
}

/**
 * @brief Checks if a block's hash meets the proof-of-work difficulty.
 * @param block A pointer to the Block to check.
 * @param difficulty The number of leading zeros required.
 * @return 0 if valid, -1 if invalid.
 */
int proof_of_work_is_valid(const Block* block, int difficulty) {
    if (block == NULL || difficulty < 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for proof_of_work_is_valid.");
        return -1;
    }

    char expected_prefix[HASH_HEX_LEN + 1];
    for (int i = 0; i < difficulty; i++) {
        expected_prefix[i] = '0';
    }
    expected_prefix[difficulty] = '\0';

    // Calculate the raw hash of the block based on its contents
    uint8_t calculated_raw_hash[SHA256_HASH_SIZE];
    block_calculate_hash(block, calculated_raw_hash);

    // Convert the calculated raw hash to its hexadecimal string representation using hasher_bytes_to_hex_buf
    char calculated_hex_hash_str[HASH_HEX_LEN + 1];
    hasher_bytes_to_hex_buf(calculated_raw_hash, SHA256_HASH_SIZE, calculated_hex_hash_str, sizeof(calculated_hex_hash_str));

    // The block->hash field should already contain the raw hash from when it was mined.
    // Convert block->hash (raw bytes) to hex for comparison and logging.
    char stored_hex_hash_str[HASH_HEX_LEN + 1];
    hasher_bytes_to_hex_buf(block->hash, SHA256_HASH_SIZE, stored_hex_hash_str, sizeof(stored_hex_hash_str));


    // For validation, we compare the block's *stored* hash (which was supposedly found during mining)
    // against the required prefix, AND we also verify that the stored hash matches a newly calculated hash.
    // This is the correct way to validate a block's integrity and PoW.

    // 1. Verify the stored hash starts with the correct prefix
    if (strncmp(stored_hex_hash_str, expected_prefix, difficulty) != 0) {
        logger_log(LOG_LEVEL_WARN, "PoW invalid for Block #%u. Stored hash '%s' does not meet difficulty target '%s'.",
                     block->index, stored_hex_hash_str, expected_prefix);
        return -1; // Stored hash doesn't meet PoW
    }

    // 2. Verify the stored hash matches the hash calculated from the block's current content
    if (memcmp(block->hash, calculated_raw_hash, SHA256_HASH_SIZE) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Block #%u hash mismatch! Stored hash does not match re-calculated hash. Tampering suspected!", block->index);
        return -1; // Hash mismatch, block is invalid
    }

    logger_log(LOG_LEVEL_DEBUG, "PoW valid and hash consistent for Block #%u. Hash starts with '%s'.", block->index, expected_prefix);
    return 0; // Valid
}
