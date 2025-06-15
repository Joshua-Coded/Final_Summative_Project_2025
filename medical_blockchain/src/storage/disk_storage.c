// src/storage/disk_storage.c
#include "disk_storage.h"
#include "../utils/logger.h"
#include "../core/transaction.h" // Needed for AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE
#include "../core/blockchain.h" // Needed for blockchain_destroy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // For mkdir
#include <errno.h>    // For errno

// Helper to write a string/binary buffer (length + data) to file
// This is used for dynamically allocated char* or uint8_t*
// Changed len parameter type to size_t and fwrite size to sizeof(size_t)
static int write_buffer(FILE* fp, const uint8_t* buffer, size_t len) {
    if (fwrite(&len, sizeof(size_t), 1, fp) != 1) return -1;
    if (len > 0) {
        if (fwrite(buffer, sizeof(uint8_t), len, fp) != len) return -1; // Removed redundant (size_t) cast
    }
    return 0;
}

// Helper to read a string/binary buffer (length + data) from file
// Returns a dynamically allocated buffer. Caller must free.
// Changed len_out parameter type to size_t* and fread size to sizeof(size_t)
static uint8_t* read_buffer(FILE* fp, size_t* len_out) { // Changed int* to size_t*
    size_t len; // Changed int to size_t
    if (fread(&len, sizeof(size_t), 1, fp) != 1) { // Changed sizeof(int) to sizeof(size_t)
        *len_out = (size_t)-1; // Indicate read error, cast -1 to size_t
        return NULL;
    }

    *len_out = len;
    if (len == 0) return NULL; // Return NULL for 0 length, no allocation needed

    uint8_t* buffer = (uint8_t*)malloc(len);
    if (buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for read buffer of size %zu.", len); // Used %zu for size_t
        return NULL;
    }

    if (fread(buffer, sizeof(uint8_t), len, fp) != len) { // Removed redundant (size_t) cast
        free(buffer);
        *len_out = (size_t)-1; // Indicate read error, cast -1 to size_t
        return NULL;
    }
    return buffer;
}


/**
 * @brief Ensures the necessary data directories exist.
 * @param path The base path to ensure (e.g., "data/blockchain").
 * @return 0 on success, -1 on failure.
 */
int disk_storage_ensure_dir(const char* path) {
    char *dup = strdup(path);
    if (!dup) {
        logger_log(LOG_LEVEL_ERROR, "Memory allocation failed for path duplication in ensure_dir.");
        return -1;
    }

    char *p = dup;
    // Skip leading slash if any
    if (p[0] == '/') p++;

    char *slash = p;
    while (*slash != '\0') {
        slash = strchr(slash, '/');
        if (slash != NULL) {
            *slash = '\0'; // Temporarily terminate the path
            // Check if directory already exists or create it
            if (mkdir(dup, 0755) != 0) {
                if (errno != EEXIST) {
                    logger_log(LOG_LEVEL_ERROR, "Failed to create directory %s: %s", dup, strerror(errno));
                    free(dup);
                    return -1;
                }
            }
            *slash = '/'; // Restore the slash
            slash++;      // Move past the slash
        } else {
            // Last component
            if (mkdir(dup, 0755) != 0) {
                if (errno != EEXIST) {
                    logger_log(LOG_LEVEL_ERROR, "Failed to create directory %s: %s", dup, strerror(errno));
                    free(dup);
                    return -1;
                }
            }
            break;
        }
    }
    free(dup);
    return 0;
}

/**
 * @brief Saves the entire blockchain to a specified file.
 * This function now explicitly serializes each field, handling variable-length strings.
 * @param blockchain A pointer to the Blockchain structure to save.
 * @param filename The path to the file where the blockchain will be saved.
 * @return 0 on success, -1 on failure.
 */
int disk_storage_save_blockchain(const Blockchain* blockchain, const char* filename) {
    if (blockchain == NULL || filename == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot save blockchain: Blockchain or filename is NULL.");
        return -1;
    }

    // Ensure the parent directory exists
    char *dir_path = strdup(filename);
    if (!dir_path) {
        logger_log(LOG_LEVEL_ERROR, "Memory allocation failed for directory path.");
        return -1;
    }
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash != NULL) {
        *last_slash = '\0'; // Null-terminate to get just the directory part
        if (disk_storage_ensure_dir(dir_path) != 0) {
            free(dir_path);
            return -1;
        }
    } else {
        // If no slash, filename is in current dir, no need to ensure specific dir
    }
    free(dir_path);


    FILE* fp = fopen(filename, "wb"); // Write binary mode
    if (fp == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to open file for writing blockchain: %s", filename);
        return -1;
    }

    logger_log(LOG_LEVEL_INFO, "Saving blockchain to %s (length: %zu)...", filename, blockchain->length);

    // Write blockchain length
    if (fwrite(&blockchain->length, sizeof(size_t), 1, fp) != 1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to write blockchain length.");
        fclose(fp);
        return -1;
    }

    // Use temporary variables for the error log to ensure they are in scope
    size_t current_block_index = 0;
    size_t current_tx_index = 0;

    // Write each block
    for (size_t i = 0; i < blockchain->length; i++) {
        // FIX: Removed & - blockchain->chain[i] is already a Block*
        const Block* block = blockchain->chain[i];
        current_block_index = block->index; // Update for error logging

        // Serialize Block fields manually
        if (fwrite(&block->index, sizeof(block->index), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block index."); goto fail_save; }
        if (fwrite(&block->timestamp, sizeof(block->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block timestamp."); goto fail_save; }
        if (fwrite(block->prev_hash, sizeof(block->prev_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block prev_hash."); goto fail_save; }
        if (fwrite(block->hash, sizeof(block->hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block hash."); goto fail_save; }
        if (fwrite(&block->nonce, sizeof(block->nonce), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block nonce."); goto fail_save; }
        if (fwrite(&block->num_transactions, sizeof(block->num_transactions), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block num_transactions."); goto fail_save; }

        // Write each transaction
        for (size_t j = 0; j < block->num_transactions; j++) {
            current_tx_index = j; // Update for error logging
            // FIX: block->transactions[j] is already a Transaction*
            const Transaction* tx = block->transactions[j];

            // Serialize Transaction fields manually, including variable-length strings
            if (fwrite(tx->transaction_id, sizeof(tx->transaction_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx ID."); goto fail_save; }
            if (fwrite(tx->sender_id, sizeof(tx->sender_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx sender ID."); goto fail_save; }
            if (fwrite(tx->recipient_id, sizeof(tx->recipient_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx recipient ID."); goto fail_save; }

            // Write encrypted medical data (length + data)
            if (write_buffer(fp, tx->encrypted_medical_data, tx->encrypted_medical_data_len) != 0) { logger_log(LOG_LEVEL_ERROR, "Failed to write encrypted medical data."); goto fail_save; }

            // Write IV and Tag (fixed size)
            if (fwrite(tx->iv, sizeof(tx->iv), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx IV."); goto fail_save; }
            if (fwrite(tx->tag, sizeof(tx->tag), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx Tag."); goto fail_save; }

            // Write signature (fixed size)
            if (fwrite(tx->signature, sizeof(tx->signature), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx signature."); goto fail_save; }
            if (fwrite(&tx->timestamp, sizeof(tx->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx timestamp."); goto fail_save; }
            if (fwrite(&tx->value, sizeof(tx->value), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx value."); goto fail_save; }
        }
    }

    fclose(fp);
    logger_log(LOG_LEVEL_INFO, "Blockchain saved successfully to %s.", filename);
    return 0;

fail_save:
    // Use the temporary variables here which are always in scope at this point
    logger_log(LOG_LEVEL_ERROR, "Critical error during blockchain save (Block #%zu, Transaction #%zu).", current_block_index, current_tx_index);
    fclose(fp);
    return -1;
}

/**
 * @brief Loads a blockchain from a specified file.
 * This function now explicitly deserializes each field, handling variable-length strings.
 * @param filename The path to the file from which the blockchain will be loaded.
 * @return A pointer to the loaded Blockchain structure on success, or NULL on failure.
 * The caller is responsible for freeing the returned Blockchain.
 */
Blockchain* disk_storage_load_blockchain(const char* filename) {
    if (filename == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot load blockchain: Filename is NULL.");
        return NULL;
    }

    FILE* fp = fopen(filename, "rb"); // Read binary mode
    if (fp == NULL) {
        logger_log(LOG_LEVEL_INFO, "Blockchain file not found at %s. Returning NULL (new chain will be created).", filename);
        return NULL; // File might not exist yet, which is fine, or first run
    }

    logger_log(LOG_LEVEL_INFO, "Loading blockchain from %s...", filename);

    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    if (blockchain == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for Blockchain.");
        fclose(fp);
        return NULL;
    }
    blockchain->chain = NULL;
    blockchain->length = 0;

    // Read blockchain length
    size_t loaded_length;
    if (fread(&loaded_length, sizeof(size_t), 1, fp) != 1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to read blockchain length from file.");
        goto fail_load;
    }
    blockchain->length = loaded_length;

    // Allocate memory for chain array of Block POINTERS, not Block structs
    // FIX: Changed sizeof(Block) to sizeof(Block*) and cast to Block**
    blockchain->chain = (Block**)malloc(blockchain->length * sizeof(Block*));
    if (blockchain->chain == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for blockchain chain array.");
        goto fail_load;
    }

    // Temporary variables for error logging in load function
    size_t current_load_block_idx = 0;
    size_t current_load_tx_idx = 0;
    Block* current_block_ptr = NULL; // Keep a pointer to the current block being processed

    // Read each block
    for (size_t i = 0; i < blockchain->length; i++) {
        // FIX: Removed & - blockchain->chain[i] needs to be assigned a newly allocated Block
        // Also, you're currently allocating an array of Block* in line 235, but then treating
        // blockchain->chain[i] as a Block struct on line 248 by taking its address.
        // This is a subtle but important structural change.
        // If blockchain->chain is an array of Block*, then each element should point to a dynamically
        // allocated Block.
        blockchain->chain[i] = (Block*)malloc(sizeof(Block));
        if (blockchain->chain[i] == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for Block #%zu.", i);
            current_load_block_idx = i; // Ensure index is set for cleanup
            goto fail_load_block; // Jump to cleanup for previously allocated blocks
        }
        Block* block = blockchain->chain[i]; // Now 'block' points to the newly allocated Block
        
        current_block_ptr = block; // Update pointer for error handling
        current_load_block_idx = i; // Update index for error logging
        block->transactions = NULL; // Initialize to NULL for safety
        block->num_transactions = 0;

        // Deserialize Block fields manually
        if (fread(&block->index, sizeof(block->index), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block index for Block #%zu.", i); goto fail_load_block; }
        if (fread(&block->timestamp, sizeof(block->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block timestamp for Block #%zu.", i); goto fail_load_block; }
        if (fread(block->prev_hash, sizeof(block->prev_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block prev_hash for Block #%zu.", i); goto fail_load_block; }
        if (fread(block->hash, sizeof(block->hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block hash for Block #%zu.", i); goto fail_load_block; }
        if (fread(&block->nonce, sizeof(block->nonce), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block nonce for Block #%zu.", i); goto fail_load_block; }
        if (fread(&block->num_transactions, sizeof(block->num_transactions), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block num_transactions for Block #%zu.", i); goto fail_load_block; }

        // Allocate memory for transactions array of POINTERS within the block
        if (block->num_transactions > 0) {
            block->transactions = (Transaction**)malloc(block->num_transactions * sizeof(Transaction*));
            if (block->transactions == NULL) {
                logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for transactions array of pointers in Block #%u.", block->index);
                goto fail_load_block;
            }

            // Read each transaction
            for (size_t j = 0; j < block->num_transactions; j++) {
                current_load_tx_idx = j; // Update index for error logging
                block->transactions[j] = (Transaction*)malloc(sizeof(Transaction));
                if (block->transactions[j] == NULL) {
                    logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for Transaction %zu in Block #%u.", j, block->index);
                    goto fail_load_tx; // Will jump to the fail_load_tx label which handles cleanup for this block
                }
                // Initialize dynamic members to NULL to avoid double-frees on error
                block->transactions[j]->encrypted_medical_data = NULL;

                // Deserialize Transaction fields manually (using -> now because block->transactions[j] is a pointer)
                if (fread(block->transactions[j]->transaction_id, sizeof(block->transactions[j]->transaction_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->sender_id, sizeof(block->transactions[j]->sender_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx sender ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->recipient_id, sizeof(block->transactions[j]->recipient_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx recipient ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }

                // Read encrypted medical data (length + data)
                block->transactions[j]->encrypted_medical_data = read_buffer(fp, &block->transactions[j]->encrypted_medical_data_len);
                // FIX: Compare size_t to (size_t)-1
                if (block->transactions[j]->encrypted_medical_data_len == (size_t)-1) { logger_log(LOG_LEVEL_ERROR, "Failed to read encrypted medical data length for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (block->transactions[j]->encrypted_medical_data == NULL && block->transactions[j]->encrypted_medical_data_len > 0) { // Should only be NULL if len is 0
                    logger_log(LOG_LEVEL_ERROR, "Failed to allocate/read encrypted medical data for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx;
                }

                // Read IV and Tag (fixed size)
                if (fread(block->transactions[j]->iv, sizeof(block->transactions[j]->iv), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx IV for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->tag, sizeof(block->transactions[j]->tag), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx Tag for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }

                // Read signature (fixed size)
                if (fread(block->transactions[j]->signature, sizeof(block->transactions[j]->signature), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx signature for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(&block->transactions[j]->timestamp, sizeof(block->transactions[j]->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx timestamp for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(&block->transactions[j]->value, sizeof(block->transactions[j]->value), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx value for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
            }
        }
    }

    fclose(fp);
    logger_log(LOG_LEVEL_INFO, "Blockchain loaded successfully from %s (length: %zu).", filename, blockchain->length);
    return blockchain;

fail_load_tx:
    logger_log(LOG_LEVEL_ERROR, "Error during transaction loading at Block #%zu, Transaction #%zu.", current_load_block_idx, current_load_tx_idx);
    // Cleanup for transactions within the current block being loaded
    if (current_block_ptr != NULL && current_block_ptr->transactions != NULL) {
        // Free the current (failed) transaction if it was allocated
        if (current_block_ptr->transactions[current_load_tx_idx] != NULL) {
            transaction_destroy(current_block_ptr->transactions[current_load_tx_idx]);
            current_block_ptr->transactions[current_load_tx_idx] = NULL; // Avoid double free if fail_load_block also calls destroy
        }
        // Free any transactions that were successfully loaded in this block
        for (size_t k = 0; k < current_load_tx_idx; k++) {
            if (current_block_ptr->transactions[k] != NULL) {
                transaction_destroy(current_block_ptr->transactions[k]);
                current_block_ptr->transactions[k] = NULL;
            }
        }
        free(current_block_ptr->transactions);
        current_block_ptr->transactions = NULL;
    }
    // Fall through to fail_load_block to handle cleanup for the current block and overall blockchain

fail_load_block:
    logger_log(LOG_LEVEL_ERROR, "Error during block loading at Block #%zu.", current_load_block_idx);
    // Cleanup for the current block and any previous blocks
    // This now correctly iterates through already allocated blocks in blockchain->chain
    // and calls transaction_destroy for their transactions, then frees the block itself.
    if (blockchain != NULL && blockchain->chain != NULL) {
        for (size_t k = 0; k <= current_load_block_idx; k++) {
            if (blockchain->chain[k] != NULL) {
                // If the block has transactions, destroy them first
                if (blockchain->chain[k]->transactions != NULL) {
                    for (size_t l = 0; l < blockchain->chain[k]->num_transactions; l++) {
                        if (blockchain->chain[k]->transactions[l] != NULL) {
                            transaction_destroy(blockchain->chain[k]->transactions[l]);
                        }
                    }
                    free(blockchain->chain[k]->transactions);
                    blockchain->chain[k]->transactions = NULL;
                }
                free(blockchain->chain[k]);
                blockchain->chain[k] = NULL;
            }
        }
        free(blockchain->chain); // Free the array of Block pointers
        blockchain->chain = NULL;
    }
    // Fall through to fail_load to handle overall blockchain structure cleanup

fail_load:
    // This label will destroy the entire blockchain structure that was being built.
    // This is the safest way to ensure all dynamically allocated memory is freed on error.
    logger_log(LOG_LEVEL_ERROR, "Total blockchain load failed.");
    if (blockchain != NULL) {
        // If blockchain_destroy handles NULL blockchain->chain safely, this is fine.
        // Otherwise, ensure chain is freed before this. The cleanup above helps.
        blockchain_destroy(blockchain); // This function must correctly free all blocks and their transactions
    }
    if (fp != NULL) fclose(fp);
    return NULL;
}
