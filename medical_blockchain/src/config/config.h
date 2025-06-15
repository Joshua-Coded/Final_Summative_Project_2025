// src/config/config.h
#ifndef CONFIG_H
#define CONFIG_H

// --- Blockchain Core Configuration ---

/**
 * @brief The mining difficulty for new blocks.
 * Represents the number of leading zero hexadecimal characters required in a block's hash.
 * A higher number means more difficult mining.
 */
#define BLOCKCHAIN_DIFFICULTY 2 // Adjust this value based on desired mining effort.

/**
 * @brief The maximum number of transactions a block can contain.
 * This is a soft limit guiding initial capacity or policy.
 */
#define MAX_TRANSACTIONS_PER_BLOCK 10 // Max transactions per block (from your blockchain_config.h)

// --- General System Configuration ---

/**
 * @brief Maximum length for sender/recipient IDs (e.g., public key hex strings).
 * Includes null terminator.
 */
#define MAX_ID_LENGTH 128

/**
 * @brief Maximum length for digital signatures (hex representation).
 * Includes null terminator.
 */
#define MAX_SIGNATURE_LENGTH 256

/**
 * @brief Default Proof-of-Work Difficulty.
 * The number of leading zeros required for a valid block hash.
 * Higher values increase mining difficulty.
 */
#define DEFAULT_DIFFICULTY 2 // For quick testing. For more realistic (but slow) mining, use 4 or 5.
#define PENDING_TRANSACTIONS_INITIAL_CAPACITY 50 
// --- Storage Paths ---

/**
 * @brief Default directory for blockchain data files.
 */
#define DEFAULT_DATA_DIR "data/blockchain"

/**
 * @brief Default filename for the main blockchain data file.
 */
#define DEFAULT_BLOCKCHAIN_FILE "blockchain.dat"

// --- Other Global Configurations (Add as needed) ---
// Example: Node network port, etc.

#endif // CONFIG_H
