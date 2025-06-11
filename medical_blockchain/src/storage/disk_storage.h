// src/storage/disk_storage.h
#ifndef DISK_STORAGE_H
#define DISK_STORAGE_H

#include "../core/blockchain.h" // Include for Blockchain struct

// Define default directory for blockchain data
#define DEFAULT_DATA_DIR "data/blockchain"
#define DEFAULT_BLOCKCHAIN_FILE "blockchain.dat"

/**
 * @brief Saves the entire blockchain to a specified file.
 * @param blockchain A pointer to the Blockchain structure to save.
 * @param filename The path to the file where the blockchain will be saved.
 * @return 0 on success, -1 on failure.
 */
int disk_storage_save_blockchain(const Blockchain* blockchain, const char* filename);

/**
 * @brief Loads a blockchain from a specified file.
 * @param filename The path to the file from which the blockchain will be loaded.
 * @return A pointer to the loaded Blockchain structure on success, or NULL on failure.
 * The caller is responsible for freeing the returned Blockchain.
 */
Blockchain* disk_storage_load_blockchain(const char* filename);

/**
 * @brief Ensures the necessary data directories exist.
 * @param path The base path to ensure (e.g., "data/blockchain").
 * @return 0 on success, -1 on failure.
 */
int disk_storage_ensure_dir(const char* path);

#endif // DISK_STORAGE_H
