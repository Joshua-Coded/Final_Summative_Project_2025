// user/user_store.h
#ifndef USER_STORE_H
#define USER_STORE_H

#include <stddef.h> // For size_t
#include "../crypto/sha256.h" // NEW: Include sha256.h to get SHA256_HEX_LEN definition

// Define maximum lengths for user fields
#define MAX_USERNAME_LEN 64
// #define SHA256_HEX_LEN 64 // REMOVED: Redefined in sha256.h, now included above
#define MAX_KEY_PEM_LEN 4096 // Sufficient for PEM encoded private/public keys
#define MAX_USER_ROLE_LEN 32 // Max length for user role

/**
 * @brief Represents a user in the system.
 */
typedef struct {
    char username[MAX_USERNAME_LEN];
    char hashed_password[SHA256_HEX_LEN + 1]; // +1 for null terminator
    char private_key_pem[MAX_KEY_PEM_LEN];
    char public_key_pem[MAX_KEY_PEM_LEN];
    char public_key_hash[SHA256_HEX_LEN + 1]; // +1 for null terminator
    char role[MAX_USER_ROLE_LEN]; // Field to store user role (e.g., "patient", "practitioner")
} User;

/**
 * @brief Initializes the user store, loading users from disk.
 * If the file does not exist, it starts with an empty store.
 * @param file_path The path to the user data file.
 * @return 0 on success, -1 on failure.
 */
int user_store_init(const char* file_path);

/**
 * @brief Adds a new user to the store and saves the updated store to disk.
 * @param user The User struct containing the new user's details.
 * @return 0 on success, -1 if username already exists or other failure.
 */
int user_store_add_user(const User* user);

/**
 * @brief Finds a user by username and copies their data into out_user.
 * @param username The username to search for.
 * @param out_user Pointer to a User struct where the found user's data will be copied.
 * @return 0 on success (user found), -1 if user not found.
 */
int user_store_find_user(const char* username, User* out_user);

/**
 * @brief Saves all current users in the in-memory store to disk.
 * @return 0 on success, -1 on failure.
 */
int user_store_save();

/**
 * @brief Shuts down the user store, freeing allocated memory.
 */
void user_store_shutdown();

#endif // USER_STORE_H

