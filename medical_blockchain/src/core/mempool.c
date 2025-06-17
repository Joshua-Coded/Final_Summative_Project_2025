#include "mempool.h"
#include "transaction.h" // For Transaction struct, transaction_is_valid, transaction_destroy, transaction_calculate_hash
#include "../utils/logger.h"
#include "../utils/linked_list.h" // Assuming you have a linked list implementation
#include "../config/config.h"    // For MAX_TRANSACTIONS_PER_BLOCK, if used
#include "../crypto/hasher.h"    // For hasher_bytes_to_hex_buf, SHA256_HASH_SIZE, HASH_HEX_LEN
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>             // ADD THIS: For bool, true, false

// Static (private to this file) linked list for the mempool
static LinkedList* g_mempool = NULL;

/**
 * @brief Initializes the mempool.
 * Must be called once before any other mempool functions.
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
 * The mempool acts as a waiting area for transactions before they are included in a block.
 * @param tx A pointer to the transaction to add. The mempool takes ownership of the transaction.
 * @return true if the transaction was successfully added, false otherwise (e.g., mempool full, invalid transaction, or duplicate).
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

    // 1. Validate the transaction itself
    if (transaction_is_valid(tx) != 0) {
        logger_log(LOG_LEVEL_WARN, "Attempted to add an invalid transaction to mempool. ID: %s", tx->transaction_id);
        transaction_destroy(tx); // Destroy invalid transaction as mempool won't take ownership
        return false;
    }

    // 2. Check for duplicates in mempool
    if (mempool_contains_transaction(tx->transaction_id)) {
        logger_log(LOG_LEVEL_WARN, "Duplicate transaction %s already in mempool. Not adding.", tx->transaction_id);
        transaction_destroy(tx); // Destroy duplicate transaction
        return false;
    }

    // 3. Check if mempool is full (optional, based on your config)
    if (linked_list_get_size(g_mempool) >= MAX_MEMPOOL_TRANSACTIONS) {
        logger_log(LOG_LEVEL_WARN, "Mempool is full. Cannot add transaction %s.", tx->transaction_id);
        transaction_destroy(tx); // Destroy transaction if mempool is full
        return false;
    }

    // 4. Add to the linked list
    if (linked_list_add(g_mempool, tx) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to add transaction %s to mempool linked list.", tx->transaction_id);
        transaction_destroy(tx); // Destroy on linked list add failure
        return false;
    }

    logger_log(LOG_LEVEL_INFO, "Transaction %s added to mempool. Current size: %zu", tx->transaction_id, linked_list_get_size(g_mempool));
    return true;
}

/**
 * @brief Retrieves a certain number of transactions from the mempool for block creation.
 * Transactions retrieved are removed from the mempool.
 * @param count The maximum number of transactions to retrieve.
 * @param output_txs An array of Transaction pointers to fill. Caller must allocate this array.
 * @return The actual number of transactions retrieved.
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
 * @brief Removes a transaction from the mempool, typically after it has been included in a block.
 * @param transaction_id The ID (hash in hex string) of the transaction to remove.
 * @return true if the transaction was found and removed, false otherwise.
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
            if (prev == NULL) { // Removing head
                g_mempool->head = current->next;
            } else {
                prev->next = current->next;
            }
            if (current == g_mempool->tail) { // Removing tail
                g_mempool->tail = prev;
            }
            
            transaction_destroy(tx); // Free the transaction data
            free(current); // Free the list node
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
 * @brief Checks if a transaction with a given ID exists in the mempool.
 * @param transaction_id The ID (hash in hex string) of the transaction to check.
 * @return true if the transaction exists, false otherwise.
 */
bool mempool_contains_transaction(const char transaction_id[TRANSACTION_ID_LEN + 1]) {
    if (g_mempool == NULL) {
        // Log an error, but don't crash. If mempool isn't init, it can't contain anything.
        logger_log(LOG_LEVEL_ERROR, "Mempool not initialized. Cannot check for transaction.");
        return false;
    }
    if (transaction_id == NULL) {
        return false; // Cannot check for a NULL ID
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
 * @brief Clears all transactions from the mempool and frees their memory.
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
            transaction_destroy((Transaction*)current->data); // Free the transaction itself
        }
        free(current); // Free the list node
        current = next;
    }
    g_mempool->head = NULL;
    g_mempool->tail = NULL;
    g_mempool->size = 0;
    linked_list_destroy(g_mempool); // Free the linked list structure
    g_mempool = NULL;
    logger_log(LOG_LEVEL_DEBUG, "Mempool cleared and destroyed.");
}

/**
 * @brief Gets the current number of transactions in the mempool.
 * @return The number of transactions in the mempool.
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
            // Assuming transaction_print doesn't need an encryption key for basic mempool print
            // If it does, you'll need to pass one, perhaps NULL, or a global/config one.
            // For now, let's assume it can take NULL or is designed to print without key.
            // If transaction_print doesn't accept NULL for the key, you might need a dedicated
            // simplified print for mempool or pass a dummy/zero-filled key.
            // Based on previous fixes, transaction_print takes `const uint8_t encryption_key[AES_256_KEY_SIZE])`.
            // So we need to provide one. For mempool, typically we don't have the key readily.
            // Let's pass a NULL. Your transaction_print needs to handle NULL encryption_key gracefully.
            logger_log(LOG_LEVEL_INFO, "  Tx %zu:", i++);
            // IMPORTANT: If transaction_print requires a valid key, even for just printing ID,
            // you might have to adjust or create a simpler print for mempool.
            // For now, passing NULL for encryption_key, expecting transaction_print to handle it.
            // Or, you could just print tx->transaction_id directly here for simplicity in mempool_print.
            // Let's print just the ID for mempool to avoid decryption complexities here.
            logger_log(LOG_LEVEL_INFO, "    ID: %s", tx->transaction_id);
            // If you want full transaction details, you'd need the key.
            // transaction_print(tx, NULL); // If it handles NULL key
        } else {
            logger_log(LOG_LEVEL_WARN, "  Tx %zu: (NULL transaction pointer in mempool)", i++);
        }
        current = current->next;
    }
    logger_log(LOG_LEVEL_INFO, "------------------------------------------");
}
