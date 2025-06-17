// src/utils/linked_list.c
#include "linked_list.h"
#include "logger.h" // Assuming you have a logger for error messages
#include <stdlib.h> // For malloc, free
#include <stdio.h>  // For NULL (though stddef.h provides it)

/**
 * @brief Creates a new empty linked list.
 * @return A pointer to the newly created LinkedList, or NULL on failure.
 */
LinkedList* linked_list_create() {
    LinkedList* list = (LinkedList*)malloc(sizeof(LinkedList));
    if (list == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for linked list.");
        return NULL;
    }
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    logger_log(LOG_LEVEL_DEBUG, "Linked list created.");
    return list;
}

/**
 * @brief Adds an element to the end of the linked list.
 * @param list A pointer to the LinkedList.
 * @param data A pointer to the data to add. The list takes ownership.
 * @return 0 on success, -1 on failure.
 */
int linked_list_add(LinkedList* list, void* data) {
    if (list == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot add to NULL linked list.");
        return -1;
    }
    if (data == NULL) {
        logger_log(LOG_LEVEL_WARN, "Attempted to add NULL data to linked list.");
        // Depending on your design, you might allow NULL data or disallow it.
        // For mempool, transactions should not be NULL, so this is an error.
        return -1;
    }

    ListNode* newNode = (ListNode*)malloc(sizeof(ListNode));
    if (newNode == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for linked list node.");
        return -1;
    }
    newNode->data = data;
    newNode->next = NULL;

    if (list->tail == NULL) { // List is empty
        list->head = newNode;
        list->tail = newNode;
    } else {
        list->tail->next = newNode;
        list->tail = newNode;
    }
    list->size++;
    logger_log(LOG_LEVEL_DEBUG, "Data added to linked list. Current size: %zu", list->size);
    return 0;
}

/**
 * @brief Removes the head (first) element from the linked list.
 * The caller becomes responsible for freeing the data removed.
 * @param list A pointer to the LinkedList.
 * @return A pointer to the data that was at the head, or NULL if the list is empty.
 */
void* linked_list_remove_head(LinkedList* list) {
    if (list == NULL || list->head == NULL) {
        // logger_log(LOG_LEVEL_DEBUG, "Attempted to remove from empty or NULL linked list.");
        return NULL; // List is empty or uninitialized
    }

    ListNode* oldHead = list->head;
    void* data = oldHead->data;

    list->head = oldHead->next;
    if (list->head == NULL) { // List became empty
        list->tail = NULL;
    }

    free(oldHead);
    list->size--;
    logger_log(LOG_LEVEL_DEBUG, "Head element removed from linked list. Current size: %zu", list->size);
    return data;
}

/**
 * @brief Gets the current size (number of elements) of the linked list.
 * @param list A pointer to the LinkedList.
 * @return The number of elements in the list. Returns 0 if list is NULL.
 */
size_t linked_list_get_size(const LinkedList* list) {
    if (list == NULL) {
        return 0;
    }
    return list->size;
}

/**
 * @brief Destroys the linked list, freeing all nodes.
 * Does NOT free the data stored in the nodes.
 * This function should only be called if the data pointers are no longer needed
 * or if the data has been freed elsewhere (e.g., in mempool_clear).
 * @param list A pointer to the LinkedList to destroy.
 */
void linked_list_destroy(LinkedList* list) {
    if (list == NULL) {
        return;
    }
    // Note: This only frees the nodes, not the data held by the nodes.
    // mempool_clear explicitly frees the Transaction data first.
    ListNode* current = list->head;
    while (current != NULL) {
        ListNode* next = current->next;
        free(current);
        current = next;
    }
    free(list); // Free the list structure itself
    logger_log(LOG_LEVEL_DEBUG, "Linked list structure destroyed.");
}
