#include "mempool.h"
#include "transaction.h"
#include "../utils/logger.h"
#include "../utils/linked_list.h"
#include "../config/config.h"
#include "../crypto/hasher.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

static LinkedList* g_mempool = NULL;

/**
 * @brief Initializes the mempool.
 */
void mempool_init() {
    if (g_mempool != NULL) {
        logger_log(LOG_LEVEL_WARN, "Mempool already initialized. Clearing existing mempool.");
        mempool_clear();
    }
    g_mempool = linked_list_create();
    if (g_mempool == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to initialize mempool: linked_list_create failed.");
    } else {
        logger_log(LOG_LEVEL_DEBUG, "Mempool initialized.");
    }
}

/**
 * @brief Adds a transaction to the mempool.
 */
bool mempool_add_transaction(Transaction* tx) {
    if (g_mempool == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Mempool not initialized. Cannot add transaction.");
        return false;
    }

    if (tx == NULL) {
        logger_log(LOG_LEVEL_WARN, "Attempted to add a NULL transaction to mempool.");
        return false;
    }

    if (transaction_is_valid(tx) != 0) {
        logger_log(LOG_LEVEL_WARN, "Attempted to add an invalid transaction to mempool. ID: %s", tx->transaction_id);
        transaction_destroy(tx);
        return false;
    }

    if (mempool_contains_transaction(tx->transaction_id)) {
        logger_log(LOG_LEVEL_WARN, "Duplicate transaction %s already in mempool. Not adding.", tx->transaction_id);
        transaction_destroy(tx);
        return false;
    }

    if (linked_list_get_size(g_mempool) >= MAX_MEMPOOL_TRANSACTIONS) {
        logger_log(LOG_LEVEL_WARN, "Mempool is full. Cannot add transaction %s.", tx->transaction_id);
        transaction_destroy(tx);
        return false;
    }

    if (linked_list_add(g_mempool, tx) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to add transaction %s to mempool linked list.", tx->transaction_id);
        transaction_destroy(tx);
        return false;
    }

    logger_log(LOG_LEVEL_INFO, "Transaction %s added to mempool. Current size: %zu", tx->transaction_id, linked_list_get_size(g_mempool));
    return true;
}

/**
 * @brief Retrieves transactions from the mempool for block creation.
 */
size_t mempool_get_transactions_for_block(size_t count, Transaction** output_txs) {
    if (g_mempool == NULL || output_txs == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Mempool not initialized or output_txs is NULL for retrieval.");
        return 0;
    }

    size_t retrieved_count = 0;
    for (size_t i = 0; i < count && linked_list_get_size(g_mempool) > 0; i++) {
        Transaction* tx = (Transaction*)linked_list_remove_head(g_mempool);
        if (tx != NULL) {
            output_txs[retrieved_count++] = tx;
        } else {
            logger_log(LOG_LEVEL_WARN, "Attempted to retrieve transaction from empty mempool node.");
        }
    }
    logger_log(LOG_LEVEL_DEBUG, "Retrieved %zu transactions from mempool for block. Remaining: %zu", retrieved_count, linked_list_get_size(g_mempool));
    return retrieved_count;
}

/**
 * @brief Removes a transaction from the mempool.
 */
bool mempool_remove_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]) {
    if (g_mempool == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Mempool not initialized. Cannot remove transaction.");
        return false;
    }

    if (transaction_id == NULL) {
        logger_log(LOG_LEVEL_WARN, "Attempted to remove NULL transaction ID from mempool.");
        return false;
    }

    ListNode* current = g_mempool->head;
    ListNode* prev = NULL;

    while (current != NULL) {
        Transaction* tx = (Transaction*)current->data;
        if (tx != NULL && strcmp(tx->transaction_id, transaction_id) == 0) {
            if (prev == NULL) {
                g_mempool->head = current->next;
            } else {
                prev->next = current->next;
            }
            if (current == g_mempool->tail) {
                g_mempool->tail = prev;
            }

            transaction_destroy(tx);
            free(current);
            g_mempool->size--;
            logger_log(LOG_LEVEL_DEBUG, "Transaction %s removed from mempool. Current size: %zu", transaction_id, linked_list_get_size(g_mempool));
            return true;
        }
        prev = current;
        current = current->next;
    }

    logger_log(LOG_LEVEL_DEBUG, "Transaction %s not found in mempool for removal.", transaction_id);
    return false;
}

/**
 * @brief Checks if a transaction exists in the mempool.
 */
bool mempool_contains_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]) {
    if (g_mempool == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Mempool not initialized. Cannot check for transaction.");
        return false;
    }
    if (transaction_id == NULL) {
        return false;
    }

    ListNode* current = g_mempool->head;
    while (current != NULL) {
        Transaction* tx = (Transaction*)current->data;
        if (tx != NULL && strcmp(tx->transaction_id, transaction_id) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

/**
 * @brief Clears all transactions from the mempool.
 */
void mempool_clear() {
    if (g_mempool == NULL) {
        logger_log(LOG_LEVEL_WARN, "Mempool is already NULL. Nothing to clear.");
        return;
    }
    logger_log(LOG_LEVEL_DEBUG, "Clearing mempool with %zu transactions.", linked_list_get_size(g_mempool));
    ListNode* current = g_mempool->head;
    while (current != NULL) {
        ListNode* next = current->next;
        if (current->data != NULL) {
            transaction_destroy((Transaction*)current->data);
        }
        free(current);
        current = next;
    }
    g_mempool->head = NULL;
    g_mempool->tail = NULL;
    g_mempool->size = 0;
    // Do NOT destroy g_mempool here, as mempool_shutdown will handle that.
    // mempool_clear is intended to just empty the list, not destroy the list structure itself.
    logger_log(LOG_LEVEL_DEBUG, "Mempool contents cleared.");
}

/**
 * @brief Gets the current number of transactions in the mempool.
 */
size_t mempool_get_size() {
    if (g_mempool == NULL) {
        return 0;
    }
    return linked_list_get_size(g_mempool);
}

/**
 * @brief Prints the contents of the mempool for debugging.
 */
void mempool_print() {
    if (g_mempool == NULL) {
        logger_log(LOG_LEVEL_INFO, "Mempool is not initialized.");
        return;
    }
    if (linked_list_get_size(g_mempool) == 0) {
        logger_log(LOG_LEVEL_INFO, "Mempool is empty.");
        return;
    }

    logger_log(LOG_LEVEL_INFO, "--- Mempool Contents (%zu transactions) ---", linked_list_get_size(g_mempool));
    ListNode* current = g_mempool->head;
    size_t i = 0;
    while (current != NULL) {
        Transaction* tx = (Transaction*)current->data;
        if (tx != NULL) {
            logger_log(LOG_LEVEL_INFO, "  Tx %zu: ID: %s", i++, tx->transaction_id);
        } else {
            logger_log(LOG_LEVEL_WARN, "  Tx %zu: (NULL transaction pointer in mempool)", i++);
        }
        current = current->next;
    }
    logger_log(LOG_LEVEL_INFO, "------------------------------------------");
}

/**
 * @brief Retrieves a specific transaction by index from the mempool.
 * This is inefficient for large mempools, but useful for CLI.
 */
const Transaction* mempool_get_transaction_by_index(size_t index) {
    if (g_mempool == NULL || index >= linked_list_get_size(g_mempool)) {
        logger_log(LOG_LEVEL_ERROR, "Invalid index %zu or mempool not initialized/empty.", index);
        return NULL;
    }

    ListNode* current = g_mempool->head;
    for (size_t i = 0; i < index; ++i) {
        current = current->next;
    }
    return (const Transaction*)current->data;
}

/**
 * @brief Shuts down the mempool, freeing any allocated resources.
 */
void mempool_shutdown() {
    logger_log(LOG_LEVEL_INFO, "Shutting down mempool...");
    // Clear all transactions and free their memory
    mempool_clear();
    // Now destroy the linked list structure itself if it exists
    if (g_mempool != NULL) {
        linked_list_destroy(g_mempool); // This assumes linked_list_destroy frees the list structure
        g_mempool = NULL;
    }
    logger_log(LOG_LEVEL_INFO, "Mempool shutdown complete.");
}
