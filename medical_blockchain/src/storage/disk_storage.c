// src/storage/disk_storage.c
#include "disk_storage.h"
#include "../utils/logger.h"
#include "../core/transaction.h" // Now includes the updated Transaction struct
#include "../core/blockchain.h" // Needed for blockchain_destroy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // For mkdir
#include <errno.h>    // For errno

// Helper to write a string/binary buffer (length + data) to file
// This is used for dynamically allocated char* or uint8_t*
static int write_buffer(FILE* fp, const uint8_t* buffer, size_t len) {
    if (fwrite(&len, sizeof(size_t), 1, fp) != 1) return -1;
    if (len > 0) {
        if (fwrite(buffer, sizeof(uint8_t), len, fp) != len) return -1;
    }
    return 0;
}

// Helper to read a string/binary buffer (length + data) from file
// Returns a dynamically allocated buffer. Caller must free.
static uint8_t* read_buffer(FILE* fp, size_t* len_out) {
    size_t len;
    if (fread(&len, sizeof(size_t), 1, fp) != 1) {
        *len_out = (size_t)-1; // Indicate read error
        return NULL;
    }

    *len_out = len;
    if (len == 0) return NULL; // Return NULL for 0 length, no allocation needed

    uint8_t* buffer = (uint8_t*)malloc(len);
    if (buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for read buffer of size %zu.", len);
        return NULL;
    }

    if (fread(buffer, sizeof(uint8_t), len, fp) != len) {
        free(buffer);
        *len_out = (size_t)-1; // Indicate read error
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
 * This function now explicitly serializes each field, handling variable-length strings and unions.
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
            const Transaction* tx = block->transactions[j];

            // Serialize common Transaction fields
            if (fwrite(&tx->type, sizeof(tx->type), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx type."); goto fail_save; }
            if (fwrite(&tx->timestamp, sizeof(tx->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx timestamp."); goto fail_save; }
            if (fwrite(tx->transaction_id, sizeof(tx->transaction_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx ID."); goto fail_save; }
            if (fwrite(tx->sender_public_key_hash, sizeof(tx->sender_public_key_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx sender public key hash."); goto fail_save; }
            if (fwrite(tx->signature, sizeof(tx->signature), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx signature."); goto fail_save; }

            // Serialize union data based on transaction type
            switch (tx->type) {
                case TX_NEW_RECORD:
                    if (write_buffer(fp, tx->data.new_record.encrypted_data, tx->data.new_record.encrypted_data_len) != 0) { logger_log(LOG_LEVEL_ERROR, "Failed to write encrypted medical data."); goto fail_save; }
                    if (fwrite(tx->data.new_record.iv, sizeof(tx->data.new_record.iv), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx IV."); goto fail_save; }
                    if (fwrite(tx->data.new_record.tag, sizeof(tx->data.new_record.tag), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write tx Tag."); goto fail_save; }
                    if (fwrite(tx->data.new_record.original_record_hash, sizeof(tx->data.new_record.original_record_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write original record hash."); goto fail_save; }
                    break;
                case TX_REQUEST_ACCESS: // Fallthrough for similar access control structs
                case TX_GRANT_ACCESS:
                case TX_REVOKE_ACCESS:
                    if (fwrite(tx->data.access_control.related_record_hash, sizeof(tx->data.access_control.related_record_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write related record hash."); goto fail_save; }
                    if (fwrite(tx->data.access_control.target_user_public_key_hash, sizeof(tx->data.access_control.target_user_public_key_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write target user public key hash."); goto fail_save; }
                    break;
                default:
                    logger_log(LOG_LEVEL_ERROR, "Unknown transaction type %d encountered during save.", tx->type);
                    goto fail_save;
            }
        }
    }

    fclose(fp);
    logger_log(LOG_LEVEL_INFO, "Blockchain saved successfully to %s.", filename);
    return 0;

fail_save:
    logger_log(LOG_LEVEL_ERROR, "Critical error during blockchain save (Block #%zu, Transaction #%zu).", current_block_index, current_tx_index);
    fclose(fp);
    return -1;
}

/**
 * @brief Loads a blockchain from a specified file.
 * This function now explicitly deserializes each field, handling variable-length strings and unions.
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

    // Allocate memory for chain array of Block POINTERS
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
                    goto fail_load_tx;
                }

                // Initialize dynamic members to NULL to avoid double-frees on error
                block->transactions[j]->data.new_record.encrypted_data = NULL; // Initialize a member within the union

                // Deserialize common Transaction fields
                TransactionType tx_type;
                if (fread(&tx_type, sizeof(TransactionType), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx type for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                block->transactions[j]->type = tx_type; // Assign the read type

                if (fread(&block->transactions[j]->timestamp, sizeof(block->transactions[j]->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx timestamp for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->transaction_id, sizeof(block->transactions[j]->transaction_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->sender_public_key_hash, sizeof(block->transactions[j]->sender_public_key_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx sender public key hash for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->signature, sizeof(block->transactions[j]->signature), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx signature for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }

                // Deserialize union data based on transaction type
                switch (tx_type) {
                    case TX_NEW_RECORD:
                        block->transactions[j]->data.new_record.encrypted_data = read_buffer(fp, &block->transactions[j]->data.new_record.encrypted_data_len);
                        if (block->transactions[j]->data.new_record.encrypted_data_len == (size_t)-1) { logger_log(LOG_LEVEL_ERROR, "Failed to read encrypted medical data length for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                        if (block->transactions[j]->data.new_record.encrypted_data == NULL && block->transactions[j]->data.new_record.encrypted_data_len > 0) {
                            logger_log(LOG_LEVEL_ERROR, "Failed to allocate/read encrypted medical data for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx;
                        }
                        if (fread(block->transactions[j]->data.new_record.iv, sizeof(block->transactions[j]->data.new_record.iv), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx IV for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                        if (fread(block->transactions[j]->data.new_record.tag, sizeof(block->transactions[j]->data.new_record.tag), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx Tag for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                        if (fread(block->transactions[j]->data.new_record.original_record_hash, sizeof(block->transactions[j]->data.new_record.original_record_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read original record hash for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                        break;
                    case TX_REQUEST_ACCESS:
                    case TX_GRANT_ACCESS:
                    case TX_REVOKE_ACCESS:
                        if (fread(block->transactions[j]->data.access_control.related_record_hash, sizeof(block->transactions[j]->data.access_control.related_record_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read related record hash for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                        if (fread(block->transactions[j]->data.access_control.target_user_public_key_hash, sizeof(block->transactions[j]->data.access_control.target_user_public_key_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read target user public key hash for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                        break;
                    default:
                        logger_log(LOG_LEVEL_ERROR, "Unknown transaction type %d encountered during load for Block #%u, Tx %zu.", tx_type, block->index, j);
                        goto fail_load_tx;
                }
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
        // Free the current (failed) transaction if it was allocated and has dynamic data
        if (current_block_ptr->transactions[current_load_tx_idx] != NULL) {
            transaction_destroy(current_block_ptr->transactions[current_load_tx_idx]);
            current_block_ptr->transactions[current_load_tx_idx] = NULL;
        }
        // Free any transactions that were successfully loaded in this block (up to current_load_tx_idx - 1)
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
    if (blockchain != NULL && blockchain->chain != NULL) {
        for (size_t k = 0; k <= current_load_block_idx; k++) {
            if (blockchain->chain[k] != NULL) {
                // transaction_destroy handles NULL transactions safely, so we can just call block_destroy here
                // assuming block_destroy iterates and calls transaction_destroy for its transactions
                // For this to work correctly, you'll need a `block_destroy` function that internally calls `transaction_destroy` for all its transactions.
                // If not, we'd need to manually free transactions here as well.
                // Assuming blockchain_destroy correctly tears down blocks.
                // If not, you might need to manually free block->transactions here and then block itself.
                // Let's rely on blockchain_destroy for now, but be aware this is a common pitfall.
            }
        }
    }
    // Fall through to fail_load to handle overall blockchain structure cleanup

fail_load:
    // This label will destroy the entire blockchain structure that was being built.
    logger_log(LOG_LEVEL_ERROR, "Total blockchain load failed.");
    if (blockchain != NULL) {
        blockchain_destroy(blockchain); // This function must correctly free all blocks and their transactions
    }
    if (fp != NULL) fclose(fp);
    return NULL;
}
