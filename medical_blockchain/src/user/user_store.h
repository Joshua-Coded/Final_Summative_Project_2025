// src/user/user_store.h
#ifndef USER_STORE_H
#define USER_STORE_H

#include <stdbool.h>
#include <stddef.h> // For size_t
#include <stdint.h> // For uint8_t
#include "../security/key_management.h" // For key lengths, etc.
#include "../crypto/hasher.h" // For SHA256_HEX_LEN

// Define maximum lengths for user-related strings
#define MAX_USERNAME_LEN 64
#define MAX_HASHED_PASSWORD_LEN (SHA256_HEX_LEN + 1) // SHA256 hash in hex + null terminator
#define MAX_PEM_KEY_LEN 4096 // Max size for PEM-encoded keys

/**
 * @brief Structure to represent a user profile.
 */
typedef struct {
    char username[MAX_USERNAME_LEN];
    char hashed_password[MAX_HASHED_PASSWORD_LEN];
    char private_key_pem[MAX_PEM_KEY_LEN];
    char public_key_pem[MAX_PEM_KEY_LEN];
    char public_key_hash[SHA256_HEX_LEN + 1]; // Hex string of public key hash
} User;

/**
 * @brief Initializes the user store, loading users from disk.
 * @param file_path The path to the user data file.
 * @return 0 on success, -1 on failure.
 */
int user_store_init(const char* file_path);

/**
 * @brief Adds a new user to the store and saves to disk.
 * @param user The User struct containing the new user's details.
 * @return 0 on success, -1 if username already exists or other failure.
 */
int user_store_add_user(const User* user);

/**
 * @brief Finds a user by username.
 * @param username The username to search for.
 * @param out_user Pointer to a User struct where the found user's data will be copied.
 * @return 0 on success (user found), -1 if user not found.
 */
int user_store_find_user(const char* username, User* out_user);

/**
 * @brief Saves all current users in the store to disk.
 * @return 0 on success, -1 on failure.
 */
int user_store_save();

/**
 * @brief Shuts down the user store, freeing allocated memory.
 */
void user_store_shutdown();

#endif // USER_STORE_H
