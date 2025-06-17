#ifndef MEMPOOL_H
#define MEMPOOL_H

#include "transaction.h" // For Transaction struct
#include <stdbool.h>     // ADD THIS: For bool type and true/false
#include <stddef.h>
// Define maximum transactions allowed in the mempool
// You might want to move this to a config.h file if it's a global configuration.
#define MAX_MEMPOOL_TRANSACTIONS 1000

/**
 * @brief Adds a transaction to the mempool.
 * The mempool acts as a waiting area for transactions before they are included in a block.
 * @param tx A pointer to the transaction to add. The mempool takes ownership of the transaction.
 * @return true if the transaction was successfully added, false otherwise (e.g., mempool full, invalid transaction, or duplicate).
 */
bool mempool_add_transaction(Transaction* tx); // Returns true if added, false if mempool full or invalid

/**
 * @brief Retrieves a certain number of transactions from the mempool for block creation.
 * Transactions retrieved are removed from the mempool.
 * @param count The maximum number of transactions to retrieve.
 * @param output_txs An array of Transaction pointers to fill. Caller must allocate this array.
 * @return The actual number of transactions retrieved.
 */
size_t mempool_get_transactions_for_block(size_t count, Transaction** output_txs);

/**
 * @brief Removes a transaction from the mempool, typically after it has been included in a block.
 * @param transaction_id The ID (hash in hex string) of the transaction to remove.
 * @return true if the transaction was found and removed, false otherwise.
 */
bool mempool_remove_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]);

/**
 * @brief Checks if a transaction with a given ID exists in the mempool.
 * @param transaction_id The ID (hash in hex string) of the transaction to check.
 * @return true if the transaction exists, false otherwise.
 */
bool mempool_contains_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]);

/**
 * @brief Initializes the mempool.
 * Must be called once before any other mempool functions.
 */
void mempool_init();

/**
 * @brief Clears all transactions from the mempool and frees their memory.
 */
void mempool_clear();

/**
 * @brief Gets the current number of transactions in the mempool.
 * @return The number of transactions in the mempool.
 */
size_t mempool_get_size();

/**
 * @brief Prints the contents of the mempool for debugging.
 */
void mempool_print();

#endif // MEMPOOL_H
