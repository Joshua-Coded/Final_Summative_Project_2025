// src/user/user_store.c
#include "user_store.h"
#include "../utils/logger.h"
#include "../utils/colors.h"
#include "../config/config.h" // For DEFAULT_DATA_DIR

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> // For errno and strerror

// Internal array to hold users in memory
static User* g_users = NULL;
static size_t g_num_users = 0;
static size_t g_users_capacity = 0;
static char g_user_data_file_path[256];

#define INITIAL_USER_CAPACITY 10

// Helper function to resize the users array
static int resize_user_array() {
    size_t new_capacity = (g_users_capacity == 0) ? INITIAL_USER_CAPACITY : g_users_capacity * 2;
    User* temp_users = (User*)realloc(g_users, new_capacity * sizeof(User));
    if (temp_users == NULL) {
        logger_log(LOG_LEVEL_FATAL, "Failed to reallocate memory for user store. Errno: %s", strerror(errno));
        return -1;
    }
    g_users = temp_users;
    g_users_capacity = new_capacity;
    logger_log(LOG_LEVEL_DEBUG, "User store capacity increased to %zu.", new_capacity);
    return 0;
}

/**
 * @brief Initializes the user store, loading users from disk.
 * If the file does not exist, it starts with an empty store.
 * @param file_path The path to the user data file.
 * @return 0 on success, -1 on failure.
 */
int user_store_init(const char* file_path) {
    if (!file_path || strlen(file_path) >= sizeof(g_user_data_file_path)) {
        logger_log(LOG_LEVEL_ERROR, "Invalid user store file path provided.");
        return -1;
    }
    strncpy(g_user_data_file_path, file_path, sizeof(g_user_data_file_path) - 1);
    g_user_data_file_path[sizeof(g_user_data_file_path) - 1] = '\0';

    FILE* file = fopen(g_user_data_file_path, "r");
    if (file == NULL) {
        if (errno == ENOENT) {
            logger_log(LOG_LEVEL_INFO, "User data file '%s' not found. Starting with empty user store.", g_user_data_file_path);
            print_yellow("User data file not found. Starting with empty user store.\n");
            g_users_capacity = INITIAL_USER_CAPACITY;
            g_users = (User*)malloc(g_users_capacity * sizeof(User));
            if (g_users == NULL) {
                logger_log(LOG_LEVEL_FATAL, "Failed to allocate initial memory for user store. Errno: %s", strerror(errno));
                return -1;
            }
            g_num_users = 0;
            return 0;
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to open user data file '%s' for reading: %s", g_user_data_file_path, strerror(errno));
            print_red("Error: Failed to open user data file '%s'.\n", g_user_data_file_path);
            return -1;
        }
    }

    // Read users from file, using fgets for each field and a delimiter
    User temp_user;
    char line_buffer[MAX_KEY_PEM_LEN + 10]; // Buffer to read lines, ensuring it's large enough for PEM
    int user_fields_read = 0; // Track how many fields for current user
    int line_num = 0; // Track line number for logging

    while (fgets(line_buffer, sizeof(line_buffer), file) != NULL) {
        line_num++;
        // Remove newline character if present
        line_buffer[strcspn(line_buffer, "\n")] = 0;

        if (strcmp(line_buffer, "---") == 0) { // End of user entry delimiter
            if (user_fields_read == 6) { // Ensure all 6 fields (username, hashed_password, private_key, public_key, public_key_hash, role) were read for the current user
                if (g_num_users == g_users_capacity) {
                    if (resize_user_array() != 0) {
                        fclose(file);
                        return -1;
                    }
                }
                g_users[g_num_users++] = temp_user; // Copy the user data
            } else {
                logger_log(LOG_LEVEL_WARN, "Corrupted user data file '%s': Incomplete user entry before delimiter at line %d. Skipping this entry.", g_user_data_file_path, line_num);
                // Optionally, you might want to return -1 here for strict error handling,
                // but skipping allows partial loading. For now, we continue to read the file.
            }
            user_fields_read = 0; // Reset for next user
            continue; // Move to the next line in the file
        }

        // Copy data based on which field we expect next
        switch (user_fields_read) {
            case 0: strncpy(temp_user.username, line_buffer, sizeof(temp_user.username) - 1); temp_user.username[sizeof(temp_user.username) - 1] = '\0'; break;
            case 1: strncpy(temp_user.hashed_password, line_buffer, sizeof(temp_user.hashed_password) - 1); temp_user.hashed_password[sizeof(temp_user.hashed_password) - 1] = '\0'; break;
            case 2: strncpy(temp_user.private_key_pem, line_buffer, sizeof(temp_user.private_key_pem) - 1); temp_user.private_key_pem[sizeof(temp_user.private_key_pem) - 1] = '\0'; break;
            case 3: strncpy(temp_user.public_key_pem, line_buffer, sizeof(temp_user.public_key_pem) - 1); temp_user.public_key_pem[sizeof(temp_user.public_key_pem) - 1] = '\0'; break;
            case 4: strncpy(temp_user.public_key_hash, line_buffer, sizeof(temp_user.public_key_hash) - 1); temp_user.public_key_hash[sizeof(temp_user.public_key_hash) - 1] = '\0'; break;
            case 5: strncpy(temp_user.role, line_buffer, sizeof(temp_user.role) - 1); temp_user.role[sizeof(temp_user.role) - 1] = '\0'; break;
            default:
                logger_log(LOG_LEVEL_WARN, "Corrupted user data file '%s': Too many fields or unexpected data at line %d. Stopping load.", g_user_data_file_path, line_num);
                fclose(file);
                return -1; // Error in format
        }
        user_fields_read++;
    }

    // After loop, check if the last entry was read completely (if file didn't end with a delimiter)
    if (user_fields_read == 6) {
        if (g_num_users == g_users_capacity) {
            if (resize_user_array() != 0) {
                fclose(file);
                return -1;
            }
        }
        g_users[g_num_users++] = temp_user;
    } else if (user_fields_read > 0) {
        logger_log(LOG_LEVEL_WARN, "Corrupted user data file '%s': Incomplete final user entry. Some users might not be loaded.", g_user_data_file_path);
        print_yellow("Warning: User data file might be corrupted. Some users might not be loaded.\n");
    }


    if (!feof(file)) {
        // This condition might still be true if fgets encountered an error other than EOF
        logger_log(LOG_LEVEL_WARN, "Error reading user data file '%s' after last processed entry: %s", g_user_data_file_path, strerror(errno));
        print_yellow("Warning: Error encountered while reading user data file.\n");
    }

    fclose(file);
    logger_log(LOG_LEVEL_INFO, "Loaded %zu users from '%s'.", g_num_users, g_user_data_file_path);
    print_green("Loaded %zu users from '%s'.\n", g_num_users, g_user_data_file_path);
    return 0;
}

/**
 * @brief Adds a new user to the store and saves the updated store to disk.
 * @param user The User struct containing the new user's details.
 * @return 0 on success, -1 if username already exists or other failure.
 */
int user_store_add_user(const User* user) {
    if (user == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Attempted to add NULL user.");
        return -1;
    }

    // Check if username already exists
    for (size_t i = 0; i < g_num_users; ++i) {
        if (strcmp(g_users[i].username, user->username) == 0) {
            logger_log(LOG_LEVEL_WARN, "User with username '%s' already exists.", user->username);
            return -1; // Username already exists
        }
    }

    if (g_num_users == g_users_capacity) {
        if (resize_user_array() != 0) {
            return -1;
        }
    }

    g_users[g_num_users++] = *user; // Copy the user data
    logger_log(LOG_LEVEL_INFO, "User '%s' added to in-memory store. Total users: %zu", user->username, g_num_users);

    // Immediately save to disk after adding a new user
    if (user_store_save() != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to save user store after adding new user '%s'.", user->username);
        // Optionally, remove from in-memory array if save fails critically.
        g_num_users--; // Rollback
        return -1;
    }
    return 0;
}

/**
 * @brief Finds a user by username.
 * @param username The username to search for.
 * @param out_user Pointer to a User struct where the found user's data will be copied.
 * @return 0 on success (user found), -1 if user not found.
 */
int user_store_find_user(const char* username, User* out_user) {
    if (username == NULL || out_user == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for user_store_find_user.");
        return -1;
    }

    for (size_t i = 0; i < g_num_users; ++i) {
        if (strcmp(g_users[i].username, username) == 0) {
            *out_user = g_users[i]; // Copy the found user's data
            logger_log(LOG_LEVEL_DEBUG, "User '%s' found in store.", username);
            return 0; // User found
        }
    }
    logger_log(LOG_LEVEL_INFO, "User '%s' not found in store.", username);
    return -1; // User not found
}

/**
 * @brief Saves all current users in the store to disk.
 * @return 0 on success, -1 on failure.
 */
int user_store_save() {
    FILE* file = fopen(g_user_data_file_path, "w"); // Overwrite mode
    if (file == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to open user data file '%s' for writing: %s", g_user_data_file_path, strerror(errno));
        print_red("Error: Failed to save user data to '%s'.\n", g_user_data_file_path);
        return -1;
    }

    for (size_t i = 0; i < g_num_users; ++i) {
        // Write each field on a new line, explicitly separating them.
        // This is robust for fields that might contain spaces or newlines (like PEM keys).
        fprintf(file, "%s\n", g_users[i].username);
        fprintf(file, "%s\n", g_users[i].hashed_password);
        fprintf(file, "%s\n", g_users[i].private_key_pem);
        fprintf(file, "%s\n", g_users[i].public_key_pem);
        fprintf(file, "%s\n", g_users[i].public_key_hash);
        fprintf(file, "%s\n", g_users[i].role);
        fprintf(file, "---\n"); // Delimiter for user entries
    }

    fclose(file);
    logger_log(LOG_LEVEL_INFO, "Saved %zu users to '%s'.", g_num_users, g_user_data_file_path);
    print_green("Saved %zu users to '%s'.\n", g_num_users, g_user_data_file_path);
    return 0;
}

/**
 * @brief Shuts down the user store, freeing allocated memory.
 */
void user_store_shutdown() {
    logger_log(LOG_LEVEL_INFO, "Shutting down user store.");
    if (g_users != NULL) {
        free(g_users);
        g_users = NULL;
    }
    g_num_users = 0;
    g_users_capacity = 0;
    logger_log(LOG_LEVEL_INFO, "User store memory freed.");
}

