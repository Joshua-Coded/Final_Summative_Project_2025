// config/blockchain_config.h
#ifndef BLOCKCHAIN_CONFIG_H
#define BLOCKCHAIN_CONFIG_H

// --- General Configuration ---
#define MAX_ID_LENGTH 128            // Max length for sender/recipient IDs
#define MAX_SIGNATURE_LENGTH 256     // Max length for digital signatures (hex representation)
#define MAX_TRANSACTIONS_PER_BLOCK 10 // Max number of transactions in a block

// --- Proof-of-Work Difficulty ---
// The number of leading zeros required for a valid block hash.
// Higher values increase mining difficulty.
#define DEFAULT_DIFFICULTY 2 // For quick testing, 2 is good. For more realistic (but slow) mining, use 4 or 5.

// --- Storage Paths ---
#define DEFAULT_DATA_DIR "data/blockchain"
#define DEFAULT_BLOCKCHAIN_FILE "blockchain.dat"

// --- Hashing Configuration ---
// SHA256 hash is 32 bytes. When represented as a hexadecimal string, it's 64 characters.
#define SHA256_HEX_LEN 64

#endif // BLOCKCHAIN_CONFIG_H
