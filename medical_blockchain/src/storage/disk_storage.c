// src/storage/disk_storage.c
#include "disk_storage.h"
#include "../utils/logger.h"
#include "../core/transaction.h" // Needed for AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // For mkdir
#include <errno.h>    // For errno

// Helper to write a string/binary buffer (length + data) to file
// This is used for dynamically allocated char* or uint8_t*
static int write_buffer(FILE* fp, const uint8_t* buffer, int len) {
    if (fwrite(&len, sizeof(int), 1, fp) != 1) return -1;
    if (len > 0) {
        if (fwrite(buffer, sizeof(uint8_t), len, fp) != (size_t)len) return -1;
    }
    return 0;
}

// Helper to read a string/binary buffer (length + data) from file
// Returns a dynamically allocated buffer. Caller must free.
static uint8_t* read_buffer(FILE* fp, int* len_out) {
    int len;
    if (fread(&len, sizeof(int), 1, fp) != 1) {
        *len_out = -1; // Indicate read error
        return NULL;
    }

    *len_out = len;
    if (len == 0) return NULL; // Return NULL for 0 length, no allocation needed

    uint8_t* buffer = (uint8_t*)malloc(len);
    if (buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for read buffer of size %d.", len);
        return NULL;
    }

    if (fread(buffer, sizeof(uint8_t), len, fp) != (size_t)len) {
        free(buffer);
        *len_out = -1; // Indicate read error
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

    // Write each block
    for (size_t i = 0; i < blockchain->length; i++) {
        const Block* block = &blockchain->chain[i];

        // Serialize Block fields manually
        if (fwrite(&block->index, sizeof(block->index), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block index."); goto fail_save; }
        if (fwrite(&block->timestamp, sizeof(block->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block timestamp."); goto fail_save; }
        if (fwrite(block->prev_hash, sizeof(block->prev_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block prev_hash."); goto fail_save; }
        if (fwrite(block->hash, sizeof(block->hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block hash."); goto fail_save; }
        if (fwrite(&block->nonce, sizeof(block->nonce), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block nonce."); goto fail_save; }
        if (fwrite(&block->num_transactions, sizeof(block->num_transactions), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to write block num_transactions."); goto fail_save; }

        // Write each transaction
        for (size_t j = 0; j < block->num_transactions; j++) {
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
    logger_log(LOG_LEVEL_ERROR, "Critical error during blockchain save (Block #%u, Transaction #%zu).", (block ? block->index : 0), (tx ? j : 0));
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

    // Allocate memory for chain array
    blockchain->chain = (Block*)malloc(blockchain->length * sizeof(Block));
    if (blockchain->chain == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for blockchain chain array.");
        goto fail_load;
    }

    // Read each block
    for (size_t i = 0; i < blockchain->length; i++) {
        Block* block = &blockchain->chain[i];
        block->transactions = NULL; // Initialize to NULL for safety
        block->num_transactions = 0;

        // Deserialize Block fields manually
        if (fread(&block->index, sizeof(block->index), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block index for Block #%zu.", i); goto fail_load_block; }
        if (fread(&block->timestamp, sizeof(block->timestamp), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block timestamp for Block #%zu.", i); goto fail_load_block; }
        if (fread(block->prev_hash, sizeof(block->prev_hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block prev_hash for Block #%zu.", i); goto fail_load_block; }
        if (fread(block->hash, sizeof(block->hash), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block hash for Block #%zu.", i); goto fail_load_block; }
        if (fread(&block->nonce, sizeof(block->nonce), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block nonce for Block #%zu.", i); goto fail_load_block; }
        if (fread(&block->num_transactions, sizeof(block->num_transactions), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read block num_transactions for Block #%zu.", i); goto fail_load_block; }

        // Allocate memory for transactions array within the block
        if (block->num_transactions > 0) {
            block->transactions = (Transaction**)malloc(block->num_transactions * sizeof(Transaction*));
            if (block->transactions == NULL) {
                logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for transactions in Block #%u.", block->index);
                goto fail_load_block;
            }

            // Read each transaction
            for (size_t j = 0; j < block->num_transactions; j++) {
                block->transactions[j] = (Transaction*)malloc(sizeof(Transaction));
                if (block->transactions[j] == NULL) {
                    logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for Transaction %zu in Block #%u.", j, block->index);
                    goto fail_load_tx;
                }
                // Initialize dynamic members to NULL to avoid double-frees on error
                block->transactions[j]->encrypted_medical_data = NULL;

                // Deserialize Transaction fields manually
                if (fread(block->transactions[j]->transaction_id, sizeof(block->transactions[j]->transaction_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->sender_id, sizeof(block->transactions[j]->sender_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx sender ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
                if (fread(block->transactions[j]->recipient_id, sizeof(block->transactions[j]->recipient_id), 1, fp) != 1) { logger_log(LOG_LEVEL_ERROR, "Failed to read tx recipient ID for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }

                // Read encrypted medical data (length + data)
                block->transactions[j]->encrypted_medical_data = read_buffer(fp, &block->transactions[j]->encrypted_medical_data_len);
                if (block->transactions[j]->encrypted_medical_data_len == -1) { logger_log(LOG_LEVEL_ERROR, "Failed to read encrypted medical data length for Block #%u, Tx %zu.", block->index, j); goto fail_load_tx; }
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
    logger_log(LOG_LEVEL_ERROR, "Error during transaction loading at Block #%zu, Transaction #%zu.", i, j);
    // This cleanup is tricky. It needs to free partial transactions in the current block,
    // and then fall through to free the current block, and then the blockchain.
    if (block->transactions[j] != NULL) {
        if (block->transactions[j]->encrypted_medical_data != NULL) free(block->transactions[j]->encrypted_medical_data);
        free(block->transactions[j]);
    }
    // Loop backwards to free any successfully loaded transactions in the current block
    for (size_t k = 0; k < j; k++) {
        transaction_destroy(block->transactions[k]); // Use transaction_destroy to free all parts
    }
    free(block->transactions); // Free the array of pointers

fail_load_block:
    logger_log(LOG_LEVEL_ERROR, "Error during block loading at Block #%zu.", i);
    // If we're here, current block (blockchain->chain[i]) might be partially filled.
    // Ensure all already-allocated blocks (0 to i-1) and their transactions are destroyed.
    // The current block (blockchain->chain[i]) and its transactions (if any) need to be destroyed.
    // For simplicity, `blockchain_destroy` will clean up everything correctly if partially loaded.
fail_load:
    blockchain_destroy(blockchain); // Use blockchain_destroy to free all allocated memory
    if (fp != NULL) fclose(fp);
    return NULL;
}
