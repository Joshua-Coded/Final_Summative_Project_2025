#ifndef MEMPOOL_H
#define MEMPOOL_H

#include "transaction.h"
#include <stdbool.h>
#include <stddef.h>

#define MAX_MEMPOOL_TRANSACTIONS 1000

/**
 * @brief Adds a transaction to the mempool.
 */
bool mempool_add_transaction(Transaction* tx);

/**
 * @brief Retrieves transactions from the mempool for block creation.
 */
size_t mempool_get_transactions_for_block(size_t count, Transaction** output_txs);

/**
 * @brief Removes a transaction from the mempool.
 */
bool mempool_remove_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]);

/**
 * @brief Checks if a transaction exists in the mempool.
 */
bool mempool_contains_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]);

/**
 * @brief Initializes the mempool.
 */
void mempool_init();

/**
 * @brief Clears all transactions from the mempool.
 */
void mempool_clear();

/**
 * @brief Gets the current number of transactions in the mempool.
 */
size_t mempool_get_size();

/**
 * @brief Prints the contents of the mempool for debugging.
 */
void mempool_print();

const Transaction* mempool_get_transaction_by_index(size_t index);

/**
 * @brief Retrieves a pointer to the first transaction in the mempool.
 * The transaction is NOT removed from the mempool. This is useful for
 * inspecting or broadcasting without immediately consuming.
 *
 * @return A pointer to the first Transaction object in the mempool, or NULL if mempool is empty.
 */
Transaction* mempool_get_first_transaction(); // <--- ADD THIS LINE

/**
 * @brief Shuts down the mempool, freeing allocated resources.
 */
void mempool_shutdown();

#endif // MEMPOOL_H
