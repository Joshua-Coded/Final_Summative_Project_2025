// src/utils/linked_list.h
#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stddef.h> // For size_t

// Node structure for the linked list
typedef struct ListNode {
    void* data;          // Pointer to the actual data stored in the node
    struct ListNode* next; // Pointer to the next node in the list
} ListNode;

// Linked List structure
typedef struct LinkedList {
    ListNode* head; // Pointer to the first node
    ListNode* tail; // Pointer to the last node
    size_t size;    // Current number of elements in the list
} LinkedList;

/**
 * @brief Creates a new empty linked list.
 * @return A pointer to the newly created LinkedList, or NULL on failure.
 */
LinkedList* linked_list_create();

/**
 * @brief Adds an element to the end of the linked list.
 * @param list A pointer to the LinkedList.
 * @param data A pointer to the data to add. The list takes ownership.
 * @return 0 on success, -1 on failure.
 */
int linked_list_add(LinkedList* list, void* data);

/**
 * @brief Removes the head (first) element from the linked list.
 * The caller becomes responsible for freeing the data removed.
 * @param list A pointer to the LinkedList.
 * @return A pointer to the data that was at the head, or NULL if the list is empty.
 */
void* linked_list_remove_head(LinkedList* list);

/**
 * @brief Gets the current size (number of elements) of the linked list.
 * @param list A pointer to the LinkedList.
 * @return The number of elements in the list. Returns 0 if list is NULL.
 */
size_t linked_list_get_size(const LinkedList* list);

/**
 * @brief Destroys the linked list, freeing all nodes.
 * Does NOT free the data stored in the nodes; assumes data will be freed by caller
 * (or that it's managed externally, e.g., in mempool_clear where transaction_destroy is called).
 * @param list A pointer to the LinkedList to destroy.
 */
void linked_list_destroy(LinkedList* list);

#endif // LINKED_LIST_H
