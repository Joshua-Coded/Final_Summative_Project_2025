// src/cli/cli.c
#include "cli/cli.h"
#include "utils/logger.h"
#include "utils/colors.h"
#include "core/blockchain.h"
#include "core/block.h"
#include "core/transaction.h"
#include "core/mempool.h"
#include "security/encryption.h"
#include "security/key_management.h"
#include "crypto/hasher.h"
#include "config/config.h"
#include "storage/disk_storage.h" // Needed for disk_storage_ensure_dir
#include "network/network.h"
#include "user/user_store.h" // NEW: Include for user authentication

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>

// NEW: Define MAX_PASSWORD_INPUT_LEN here
#define MAX_PASSWORD_INPUT_LEN 256

// Global blockchain instance
static Blockchain* g_current_blockchain = NULL;
// Path for the blockchain data file
static char g_blockchain_file_path[256];
// Path for the user data file
static char g_user_data_file_path[256];

// Global active user/wallet keys for the current CLI session
static char g_cli_private_key_pem[4096] = {0};
static char g_cli_public_key_pem[4096] = {0};
static char g_cli_public_key_hash[SHA256_HEX_LEN + 1] = {0};
static char g_current_username[MAX_USERNAME_LEN] = {0}; // NEW: Store current logged-in username

// This static key is used for decrypting medical records in the CLI.
// For a real blockchain, symmetric keys would be exchanged/encrypted via asymmetric cryptography.
static uint8_t g_cli_decryption_key[AES_256_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};
static int g_cli_decryption_key_initialized = 0; // Flag to indicate if the key is considered 'ready'

// Forward declarations for CLI command handlers and helpers
static void to_lowercase(char* str);
static void get_string_input(const char* prompt, char* buffer, size_t buffer_size);
static int get_int_input(const char* prompt);
static void get_password_input(const char* prompt, char* buffer, size_t buffer_size); // NEW: For password input
static void print_help_menu();
static void handle_create_blockchain_interactive(Blockchain** bc);
static void handle_load_blockchain_interactive(Blockchain** bc, const char* blockchain_file_path);
static void handle_save_blockchain_interactive(Blockchain* bc, const char* blockchain_file_path);
static void handle_add_transaction_interactive(Blockchain* bc);
static void handle_mine_block_interactive(Blockchain* bc);
static void handle_validate_chain_interactive(Blockchain* bc);
static void handle_print_chain_interactive(Blockchain* bc, const uint8_t* encryption_key);
static void handle_view_transaction_interactive(Blockchain* bc);
static void handle_view_block_by_hash_interactive(Blockchain* bc);
static void handle_view_block_by_height_interactive(Blockchain* bc);
static void handle_print_mempool_interactive();
static void handle_set_log_level_interactive();
static void handle_start_listener_interactive();
static void handle_connect_peer_interactive();
static void handle_send_test_message_interactive(); // FIX: Removed duplicate 'void'
// static void handle_generate_keys_interactive(); // No longer a direct CLI command, integrated into register
static void handle_broadcast_transaction_interactive(Blockchain* bc);

// NEW: Authentication handlers
static void handle_register_user_interactive();
static void handle_login_user_interactive();
static void handle_logout_user_interactive();

/**
 * @brief Converts a string to lowercase.
 * @param str The string to convert.
 */
static void to_lowercase(char* str) {
    for (char *p = str; *p; p++) {
        *p = tolower(*p);
    }
}

/**
 * @brief Gets a string input from the user.
 * @param prompt The prompt to display.
 * @param buffer The buffer to store the input.
 * @param buffer_size The maximum size of the buffer.
 */
static void get_string_input(const char* prompt, char* buffer, size_t buffer_size) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error reading input or EOF reached.");
        buffer[0] = '\0';
    }
    buffer[strcspn(buffer, "\n")] = 0; // Remove trailing newline
}

/**
 * @brief Gets an integer input from the user.
 * @param prompt The prompt to display.
 * @return The integer entered by the user.
 */
static int get_int_input(const char* prompt) {
    char buffer[256];
    get_string_input(prompt, buffer, sizeof(buffer));
    return atoi(buffer);
}

/**
 * @brief Gets a password input from the user (without echoing characters).
 * Note: This is a simplified version and may not work on all terminals/OSes without ncurses or similar.
 * For this project, it simply acts like get_string_input, but conceptually indicates password.
 * In a real application, you'd use platform-specific functions (e.g., `_getch` on Windows, `termios` on Linux/macOS).
 * @param prompt The prompt to display.
 * @param buffer The buffer to store the password.
 * @param buffer_size The maximum size of the buffer.
 */
static void get_password_input(const char* prompt, char* buffer, size_t buffer_size) {
    printf("%s", prompt);
    fflush(stdout);
    // This is a simplified placeholder. For actual hidden input, you'd need platform-specific code.
    // E.g., using termios.h on Linux/macOS or <conio.h> for _getch() on Windows.
    // For this project, we'll just use fgets for simplicity.
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error reading password input or EOF reached.");
        buffer[0] = '\0';
    }
    buffer[strcspn(buffer, "\n")] = 0; // Remove trailing newline
}

/**
 * @brief Runs the main CLI loop.
 * @return 0 on successful exit, 1 on initialization failure.
 */
int cli_run() {
    if (logger_init("blockchain_cli.log") != 0) {
        fprintf(stderr, ANSI_COLOR_RED "Failed to initialize logger.\n" ANSI_COLOR_RESET);
        return 1;
    }
    logger_set_level(LOG_LEVEL_INFO);

    logger_log(LOG_LEVEL_INFO, "Blockchain CLI started (interactive mode).");

    // Initialize file paths
    snprintf(g_blockchain_file_path, sizeof(g_blockchain_file_path), "%s/%s", DEFAULT_DATA_DIR, DEFAULT_BLOCKCHAIN_FILENAME);
    snprintf(g_user_data_file_path, sizeof(g_user_data_file_path), "%s/users/users.dat", DEFAULT_DATA_DIR);

    // Ensure necessary directories exist
    if (disk_storage_ensure_dir(DEFAULT_DATA_DIR) != 0 ||
        disk_storage_ensure_dir("data/keys") != 0 ||
        disk_storage_ensure_dir("data/keys/private_keys") != 0 ||
        disk_storage_ensure_dir("data/keys/public_keys") != 0 ||
        disk_storage_ensure_dir("data/users") != 0) { // NEW: Ensure users directory exists
        logger_log(LOG_LEVEL_FATAL, "Failed to create necessary data directories. Exiting.");
        logger_shutdown();
        return EXIT_FAILURE;
    }

    if (network_init() != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to initialize network module. Exiting.");
        logger_shutdown();
        return EXIT_FAILURE;
    }

    // FIX: Removed check for mempool_init() return value here as it's typically void.
    // If mempool_init() can fail and should return an int, you'd need to update mempool.h and mempool.c first.
    mempool_init(); 

    // NEW: Initialize user store
    if (user_store_init(g_user_data_file_path) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to initialize user store. Exiting.");
        mempool_shutdown();
        network_shutdown();
        logger_shutdown();
        return EXIT_FAILURE;
    }

    // Mark the global CLI decryption key as initialized for use in block_print/transaction_print
    g_cli_decryption_key_initialized = 1;

    // Initial CLI state (no user logged in)
    g_cli_private_key_pem[0] = '\0';
    g_cli_public_key_pem[0] = '\0';
    g_cli_public_key_hash[0] = '\0';
    g_current_username[0] = '\0';

    char command[256];
    int running = 1;

    printf(ANSI_COLOR_CYAN ANSI_STYLE_BOLD "\n==============================================\n");
    printf("  Welcome to the Medical Blockchain CLI!\n");
    printf("==============================================\n" ANSI_COLOR_RESET);
    printf("Type " ANSI_COLOR_YELLOW "'help'" ANSI_COLOR_RESET " for a list of commands, or " ANSI_COLOR_YELLOW "'exit'" ANSI_COLOR_RESET " to quit.\n");
    printf("Please " ANSI_COLOR_YELLOW "'register'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'login'" ANSI_COLOR_RESET " to use authenticated commands.\n");

    while (running) {
        printf(ANSI_COLOR_BLUE "\nBlockchain CLI > " ANSI_COLOR_RESET);
        if (strlen(g_current_username) > 0) {
            printf(ANSI_COLOR_GREEN "[%s] " ANSI_COLOR_RESET, g_current_username);
        }
        if (strlen(g_cli_public_key_hash) > 0) {
            printf(ANSI_COLOR_YELLOW "(Wallet: %.10s...) " ANSI_COLOR_RESET, g_cli_public_key_hash);
        }
        printf("> ");
        fflush(stdout);

        if (fgets(command, sizeof(command), stdin) == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Error reading input or EOF reached.");
            break;
        }
        command[strcspn(command, "\n")] = 0; // Remove trailing newline

        char *token = strtok(command, " ");
        if (token == NULL) {
            continue;
        }

        to_lowercase(token);

        if (strcmp(token, "help") == 0) {
            print_help_menu();
        } else if (strcmp(token, "register") == 0) { // NEW: Register command
            handle_register_user_interactive();
        } else if (strcmp(token, "login") == 0) { // NEW: Login command
            handle_login_user_interactive();
        } else if (strcmp(token, "logout") == 0) { // NEW: Logout command
            handle_logout_user_interactive();
        } else if (strcmp(token, "create-blockchain") == 0) {
            handle_create_blockchain_interactive(&g_current_blockchain);
        } else if (strcmp(token, "load-blockchain") == 0) {
            handle_load_blockchain_interactive(&g_current_blockchain, g_blockchain_file_path);
        } else if (strcmp(token, "save-blockchain") == 0) {
            handle_save_blockchain_interactive(g_current_blockchain, g_blockchain_file_path);
        } else if (strcmp(token, "add-transaction") == 0) {
            handle_add_transaction_interactive(g_current_blockchain);
        } else if (strcmp(token, "mine-block") == 0) {
            handle_mine_block_interactive(g_current_blockchain);
        } else if (strcmp(token, "validate-chain") == 0) {
            handle_validate_chain_interactive(g_current_blockchain);
        } else if (strcmp(token, "print-chain") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (sub_command != NULL && strcmp(sub_command, "--decrypt") == 0) {
                if (g_cli_decryption_key_initialized) {
                    handle_print_chain_interactive(g_current_blockchain, g_cli_decryption_key);
                } else {
                    printf(ANSI_COLOR_RED "Decryption key not initialized. Cannot decrypt.\n" ANSI_COLOR_RESET);
                    logger_log(LOG_LEVEL_WARN, "Attempted decryption without initialized key.");
                    handle_print_chain_interactive(g_current_blockchain, NULL);
                }
            } else {
                handle_print_chain_interactive(g_current_blockchain, NULL);
            }
        } else if (strcmp(token, "view-transaction") == 0) {
            handle_view_transaction_interactive(g_current_blockchain);
        } else if (strcmp(token, "view-block-hash") == 0) {
            handle_view_block_by_hash_interactive(g_current_blockchain);
        } else if (strcmp(token, "view-block-height") == 0) {
            handle_view_block_by_height_interactive(g_current_blockchain);
        } else if (strcmp(token, "print-mempool") == 0) {
            handle_print_mempool_interactive();
        } else if (strcmp(token, "generate-keys") == 0) {
            printf(ANSI_COLOR_YELLOW "Keys are now generated automatically upon 'register' or can be managed manually by loading specific PEM files if direct key management functions were exposed. This command is deprecated.\n" ANSI_COLOR_RESET);
        } else if (strcmp(token, "broadcast-transaction") == 0) {
            handle_broadcast_transaction_interactive(g_current_blockchain);
        } else if (strcmp(token, "set-log-level") == 0) {
            handle_set_log_level_interactive();
        } else if (strcmp(token, "start-listener") == 0) {
            handle_start_listener_interactive();
        } else if (strcmp(token, "connect-peer") == 0) {
            handle_connect_peer_interactive();
        } else if (strcmp(token, "send-test-message") == 0) {
            handle_send_test_message_interactive();
        } else if (strcmp(token, "exit") == 0 || strcmp(token, "quit") == 0) {
            running = 0;
            printf(ANSI_COLOR_CYAN "Exiting Medical Blockchain CLI. Goodbye!\n" ANSI_COLOR_RESET);
            logger_log(LOG_LEVEL_INFO, "Exiting CLI.");
        } else {
            printf(ANSI_COLOR_RED "Unknown command: '%s'. " ANSI_COLOR_RESET "Type " ANSI_COLOR_YELLOW "'help'" ANSI_COLOR_RESET " for options.\n", token);
            logger_log(LOG_LEVEL_WARN, "Unknown command: '%s'. Type 'help' for options.", token);
        }
    }

    if (g_current_blockchain) {
        blockchain_destroy(g_current_blockchain);
        g_current_blockchain = NULL;
    }
    mempool_shutdown();
    network_shutdown();
    user_store_shutdown(); // NEW: Shutdown user store
    logger_shutdown();
    return 0;
}

/**
 * @brief Prints the help menu for the CLI.
 */
static void print_help_menu() {
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "\n--- Available Commands ---\n" ANSI_COLOR_RESET);
    printf("  " ANSI_COLOR_YELLOW "help" ANSI_COLOR_RESET "                     : Display this help menu.\n");
    printf("  " ANSI_COLOR_BLUE "register" ANSI_COLOR_RESET "                 : Register a new user account with associated keys.\n"); // NEW
    printf("  " ANSI_COLOR_BLUE "login" ANSI_COLOR_RESET "                    : Log in as an existing user.\n"); // NEW
    printf("  " ANSI_COLOR_BLUE "logout" ANSI_COLOR_RESET "                   : Log out the current user.\n"); // NEW
    printf("  " ANSI_COLOR_GREEN "create-blockchain" ANSI_COLOR_RESET "          : Creates a new blockchain with a genesis block.\n");
    printf("  " ANSI_COLOR_GREEN "load-blockchain" ANSI_COLOR_RESET "            : Loads an existing blockchain from disk.\n");
    printf("  " ANSI_COLOR_GREEN "save-blockchain" ANSI_COLOR_RESET "            : Saves the current blockchain to disk.\n");
    printf("  " ANSI_COLOR_GREEN "add-transaction" ANSI_COLOR_RESET "          : Adds a new record transaction (requires login).\n"); // Updated description
    printf("  " ANSI_COLOR_GREEN "mine-block" ANSI_COLOR_RESET "               : Mines a new block with pending transactions (requires login).\n"); // Updated description
    printf("  " ANSI_COLOR_GREEN "validate-chain" ANSI_COLOR_RESET "           : Validates the integrity of the blockchain.\n");
    printf("  " ANSI_COLOR_GREEN "print-chain" ANSI_COLOR_RESET " [" ANSI_COLOR_YELLOW "--decrypt" ANSI_COLOR_RESET "] : Prints all blocks. Use --decrypt for medical data.\n");
    printf("  " ANSI_COLOR_GREEN "view-transaction <ID>" ANSI_COLOR_RESET " : Displays details of a specific transaction by its ID.\n");
    printf("  " ANSI_COLOR_GREEN "view-block-hash <HASH>" ANSI_COLOR_RESET "  : Displays details of a specific block by its hash.\n");
    printf("  " ANSI_COLOR_GREEN "view-block-height <HEIGHT>" ANSI_COLOR_RESET ": Displays details of a specific block by its height.\n");
    printf("  " ANSI_COLOR_GREEN "print-mempool" ANSI_COLOR_RESET "          : Prints all transactions in the mempool.\n");
    // printf("  " ANSI_COLOR_GREEN "generate-keys" ANSI_COLOR_RESET " [--output-private <path>] [--output-public <path>] [--name <str>]: Generates new ECDSA keys for the CLI.\n"); // Deprecated
    printf("  " ANSI_COLOR_GREEN "broadcast-transaction" ANSI_COLOR_RESET ": Broadcasts the first pending transaction (requires login).\n"); // Updated description
    printf("  " ANSI_COLOR_CYAN "set-log-level" ANSI_COLOR_RESET "            : Set the logger level.\n");
    printf("  " ANSI_COLOR_BLUE "start-listener <port>" ANSI_COLOR_RESET "  : Starts listening for connections.\n");
    printf("  " ANSI_COLOR_BLUE "connect-peer <ip> <port>" ANSI_COLOR_RESET ": Connects to a remote peer.\n");
    printf("  " ANSI_COLOR_BLUE "send-test-message <msg>" ANSI_COLOR_RESET ": Sends a test message to peers.\n");
    printf("  " ANSI_COLOR_RED "exit | quit" ANSI_COLOR_RESET "            : Exits the CLI application.\n");
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--------------------------\n" ANSI_COLOR_RESET);
}

/**
 * @brief Handles the creation of a new blockchain interactively.
 * @param bc Pointer to the blockchain pointer.
 */
static void handle_create_blockchain_interactive(Blockchain** bc) {
    if (*bc != NULL) {
        printf(ANSI_COLOR_YELLOW "Blockchain already exists in memory. Destroying and recreating...\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "Blockchain already exists in memory. Destroying and recreating.");
        blockchain_destroy(*bc);
        *bc = NULL;
    }
    printf(ANSI_COLOR_CYAN "Creating new blockchain...\n" ANSI_COLOR_RESET);
    *bc = blockchain_create();
    if (*bc) {
        logger_log(LOG_LEVEL_INFO, "Blockchain created successfully with a genesis block.");
        printf(ANSI_COLOR_GREEN "New blockchain created successfully with a genesis block!\n" ANSI_COLOR_RESET);
        printf("Remember to " ANSI_COLOR_YELLOW "'save-blockchain'" ANSI_COLOR_RESET " to persist it.\n");
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create blockchain.");
        printf(ANSI_COLOR_RED "Failed to create blockchain.\n" ANSI_COLOR_RESET);
    }
}

/**
 * @brief Handles loading a blockchain from disk interactively.
 * @param bc Pointer to the blockchain pointer.
 * @param blockchain_file_path Path to the blockchain file.
 */
static void handle_load_blockchain_interactive(Blockchain** bc, const char* blockchain_file_path) {
    if (*bc != NULL) {
        printf(ANSI_COLOR_YELLOW "A blockchain is already loaded. Discarding in-memory chain before loading...\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "A blockchain is already loaded. Discarding in-memory chain before loading.");
        blockchain_destroy(*bc);
        *bc = NULL;
    }

    printf(ANSI_COLOR_CYAN "Attempting to load blockchain from '%s'...\n" ANSI_COLOR_RESET, blockchain_file_path);
    *bc = disk_storage_load_blockchain(blockchain_file_path);
    if (*bc) {
        logger_log(LOG_LEVEL_INFO, "Blockchain loaded successfully from '%s' (length: %zu).", blockchain_file_path, (*bc)->length);
        printf(ANSI_COLOR_GREEN "Blockchain loaded successfully! " ANSI_COLOR_RESET "Current chain length: " ANSI_COLOR_YELLOW "%zu\n" ANSI_COLOR_RESET, (*bc)->length);
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to load blockchain from '%s'. It might not exist.", blockchain_file_path);
        printf(ANSI_COLOR_RED "Failed to load blockchain from '%s'. " ANSI_COLOR_RESET "It might not exist or is corrupted. Try " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET ".\n", blockchain_file_path);
    }
}

/**
 * @brief Handles saving the current blockchain to disk interactively.
 * @param bc Pointer to the blockchain.
 * @param blockchain_file_path Path to the blockchain file.
 */
static void handle_save_blockchain_interactive(Blockchain* bc, const char* blockchain_file_path) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "No blockchain in memory to save.");
        printf(ANSI_COLOR_RED "No blockchain is currently loaded in memory to save. " ANSI_COLOR_RESET "Use " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'load-blockchain'" ANSI_COLOR_RESET " first.\n");
        return;
    }
    printf(ANSI_COLOR_CYAN "Saving blockchain to '%s'...\n" ANSI_COLOR_RESET, blockchain_file_path);
    if (disk_storage_save_blockchain(bc, blockchain_file_path) == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain saved successfully to '%s'.", blockchain_file_path);
        printf(ANSI_COLOR_GREEN "Blockchain saved successfully!\n" ANSI_COLOR_RESET);
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to save blockchain to '%s'.", blockchain_file_path);
        printf(ANSI_COLOR_RED "Failed to save blockchain. " ANSI_COLOR_RESET "Check logs for details.\n");
    }
}

/**
 * @brief Handles adding a new transaction interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_add_transaction_interactive(Blockchain* bc) {
    // NEW: Check for authenticated user
    if (strlen(g_current_username) == 0) {
        printf(ANSI_COLOR_RED "Error: You must be logged in to add a transaction. Please 'login' or 'register'.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "Attempted add-transaction without login.");
        return;
    }

    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot add transaction.");
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'load-blockchain'" ANSI_COLOR_RESET " first.\n");
        return;
    }

    // Using g_cli_private_key_pem etc. which are now set by login
    if (strlen(g_cli_private_key_pem) == 0 || strlen(g_cli_public_key_hash) == 0) {
        logger_log(LOG_LEVEL_ERROR, "No active ECDSA keys (after login). Cannot sign transaction. This is an internal error if logged in.");
        printf(ANSI_COLOR_RED "Internal Error: No active ECDSA keys. Please report this. (You should be logged in).\n" ANSI_COLOR_RESET);
        return;
    }

    const char* sender_public_key_hash = g_cli_public_key_hash;
    char medical_data_input[1024];
    get_string_input("Enter Medical Record Data (e.g., {\"patient\":\"John Doe\", \"diagnosis\":\"Flu\"}): ", medical_data_input, sizeof(medical_data_input));

    if (strlen(medical_data_input) == 0) {
        printf(ANSI_COLOR_YELLOW "No medical data entered. Transaction will not be created.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "No medical data entered for transaction.");
        return;
    }

    size_t medical_data_len = strlen(medical_data_input);
    uint8_t iv[AES_GCM_IV_SIZE];
    uint8_t tag[AES_GCM_TAG_SIZE];
    char original_data_hash_hex[SHA256_HEX_LEN + 1];
    uint8_t* encrypted_data_buffer = NULL;
    int encrypted_data_len = 0;

    printf(ANSI_COLOR_CYAN "Adding a new record transaction...\n" ANSI_COLOR_RESET);

    // FIX: Use the global g_cli_decryption_key for encryption
    const uint8_t* encryption_key_for_tx = g_cli_decryption_key;

    if (encryption_generate_random_bytes(iv, AES_GCM_IV_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate IV for transaction.");
        printf(ANSI_COLOR_RED "Failed to generate IV.\n" ANSI_COLOR_RESET);
        return;
    }

    encrypted_data_len = encryption_encrypt_aes_gcm(
        (const uint8_t*)medical_data_input,
        (int)medical_data_len,
        encryption_key_for_tx, // Use the global key here for encryption
        iv,
        &encrypted_data_buffer,
        tag
    );

    if (encrypted_data_len <= 0 || encrypted_data_buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to encrypt medical data for transaction (len: %d).", encrypted_data_len);
        printf(ANSI_COLOR_RED "Failed to encrypt medical data.\n" ANSI_COLOR_RESET);
        if (encrypted_data_buffer) free(encrypted_data_buffer);
        return;
    }

    uint8_t original_data_hash_binary[SHA256_DIGEST_LENGTH];
    if (hasher_sha256((const uint8_t*)medical_data_input, medical_data_len, original_data_hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash original medical data.");
        printf(ANSI_COLOR_RED "Failed to hash original medical data.\n" ANSI_COLOR_RESET);
        free(encrypted_data_buffer);
        return;
    }
    hasher_bytes_to_hex_buf(original_data_hash_binary, SHA256_DIGEST_LENGTH, original_data_hash_hex, sizeof(original_data_hash_hex));

    Transaction* tx = transaction_create(
        TX_NEW_RECORD,
        sender_public_key_hash,
        g_cli_public_key_pem
    );

    if (tx) {
        if (transaction_set_new_record_data(tx,
                                             encrypted_data_buffer,
                                             (size_t)encrypted_data_len,
                                             iv, tag, original_data_hash_hex) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to set new record data for transaction.");
            printf(ANSI_COLOR_RED "Failed to set new record data for transaction.\n" ANSI_COLOR_RESET);
            transaction_destroy(tx);
            free(encrypted_data_buffer);
            return;
        }

        if (transaction_sign(tx, g_cli_private_key_pem) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to sign sample transaction.");
            printf(ANSI_COLOR_RED "Failed to sign sample transaction. Check logs for details.\n" ANSI_COLOR_RESET);
            transaction_destroy(tx);
            free(encrypted_data_buffer);
            return;
        }

        logger_log(LOG_LEVEL_INFO, "Sample transaction created and signed with ID: %s", tx->transaction_id);
        if (mempool_add_transaction(tx) == false) {
            logger_log(LOG_LEVEL_ERROR, "Failed to add transaction to mempool (mempool full or duplicate).");
            printf(ANSI_COLOR_RED "Failed to add transaction to mempool (mempool full or duplicate).\n" ANSI_COLOR_RESET);
            transaction_destroy(tx);
        } else {
            logger_log(LOG_LEVEL_INFO, "Transaction added to mempool. Mine a block to include it!");
            printf(ANSI_COLOR_GREEN "Transaction (ID: %.10s...) added to mempool. " ANSI_COLOR_RESET "Remember to " ANSI_COLOR_YELLOW "'mine-block'" ANSI_COLOR_RESET " to include it in the chain.\n", tx->transaction_id);
        }
        free(encrypted_data_buffer); // Free the encrypted data buffer as it's copied into the transaction
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create base transaction object.");
        printf(ANSI_COLOR_RED "Failed to create base transaction object.\n" ANSI_COLOR_RESET);
        if (encrypted_data_buffer) free(encrypted_data_buffer);
    }
}

/**
 * @brief Handles mining a new block interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_mine_block_interactive(Blockchain* bc) {
    // NEW: Check for authenticated user
    if (strlen(g_current_username) == 0) {
        printf(ANSI_COLOR_RED "Error: You must be logged in to mine a block. Please 'login' or 'register'.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "Attempted mine-block without login.");
        return;
    }

    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot mine block.");
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'load-blockchain'" ANSI_COLOR_RESET " first.\n");
        return;
    }
    printf(ANSI_COLOR_CYAN "Attempting to mine a new block...\n" ANSI_COLOR_RESET);
    if (blockchain_mine_new_block(bc) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to mine a new block.");
        printf(ANSI_COLOR_RED "Failed to mine a new block. " ANSI_COLOR_RESET "(Perhaps no pending transactions or an issue with Proof-of-Work?)\n");
    } else {
        logger_log(LOG_LEVEL_INFO, "New block mined successfully! Current blockchain height: %zu", bc->length);
        printf(ANSI_COLOR_GREEN "New block mined and added to the chain!\n" ANSI_COLOR_RESET);
        printf("Current chain length: " ANSI_COLOR_YELLOW "%zu\n" ANSI_COLOR_RESET, bc->length);
        handle_save_blockchain_interactive(bc, g_blockchain_file_path);
    }
}

/**
 * @brief Handles validating the blockchain interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_validate_chain_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Nothing to validate.");
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. Nothing to validate.\n" ANSI_COLOR_RESET);
        return;
    }
    printf(ANSI_COLOR_CYAN "Validating blockchain integrity...\n" ANSI_COLOR_RESET);
    if (blockchain_is_valid(bc) == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain is valid.");
        printf(ANSI_COLOR_GREEN "Blockchain is VALID!\n" ANSI_COLOR_RESET);
    } else {
        logger_log(LOG_LEVEL_ERROR, "Blockchain is INVALID!");
        printf(ANSI_COLOR_RED "Blockchain is INVALID! " ANSI_COLOR_RESET "Check logs for details on potential tampering.\n");
    }
}

/**
 * @brief Handles printing the blockchain interactively.
 * @param bc Pointer to the blockchain.
 * @param encryption_key The key to use for decryption, or NULL if none.
 */
static void handle_print_chain_interactive(Blockchain* bc, const uint8_t* encryption_key) {
    if (bc == NULL || bc->length == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain is empty, nothing to print.");
        printf(ANSI_COLOR_YELLOW "Blockchain is empty, nothing to print.\n" ANSI_COLOR_RESET);
        return;
    }
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "\n--- Printing Blockchain (Length: %zu) ---\n" ANSI_COLOR_RESET, bc->length);
    for (size_t i = 0; i < bc->length; ++i) {
        Block* b = blockchain_get_block_by_index(bc, i);
        if (b) {
            printf(ANSI_COLOR_CYAN "\n--- Block #%zu ---\n" ANSI_COLOR_RESET, i);
            block_print(b, encryption_key);
            printf(ANSI_COLOR_CYAN "-----------------\n" ANSI_COLOR_RESET);
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to retrieve block at index %zu for printing.", i);
        }
    }
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--- End of Blockchain Print ---\n" ANSI_COLOR_RESET);
}

/**
 * @brief Handles viewing a transaction by ID interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_view_transaction_interactive(Blockchain* bc) {
    if (!bc) {
        printf(ANSI_COLOR_RED "No blockchain loaded. Create or load one first to view transactions.\n" ANSI_COLOR_RESET);
        return;
    }
    char transaction_id[TRANSACTION_ID_LEN + 1];
    get_string_input("Enter Transaction ID (hex): ", transaction_id, sizeof(transaction_id));

    if (strlen(transaction_id) == 0) {
        printf(ANSI_COLOR_YELLOW "Transaction ID cannot be empty.\n" ANSI_COLOR_RESET);
        return;
    }
    if (strlen(transaction_id) != SHA256_HEX_LEN) {
        printf(ANSI_COLOR_RED "Invalid Transaction ID length. Must be %d characters.\n" ANSI_COLOR_RESET, SHA256_HEX_LEN);
        return;
    }

    const Transaction* found_tx = blockchain_get_transaction(bc, transaction_id);
    if (found_tx) {
        printf(ANSI_COLOR_GREEN "Transaction Found:\n" ANSI_COLOR_RESET);
        if (g_cli_decryption_key_initialized) {
            transaction_print(found_tx, g_cli_decryption_key);
        } else {
            logger_log(LOG_LEVEL_WARN, "Decryption key not initialized. Printing transaction without decrypting data.");
            printf(ANSI_COLOR_YELLOW "Warning: Decryption key not available. Medical data will be encrypted.\n" ANSI_COLOR_RESET);
            transaction_print(found_tx, NULL);
        }
    } else {
        printf(ANSI_COLOR_RED "Transaction not found.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Transaction %s not found.", transaction_id);
    }
}

/**
 * @brief Handles viewing a block by hash interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_view_block_by_hash_interactive(Blockchain* bc) {
    if (!bc) {
        printf(ANSI_COLOR_RED "No blockchain loaded. Create or load one first to view blocks.\n" ANSI_COLOR_RESET);
        return;
    }
    char hash_buffer[SHA256_HEX_LEN + 1];
    get_string_input("Enter Block Hash (hex): ", hash_buffer, sizeof(hash_buffer));

    if (strlen(hash_buffer) == 0) {
        printf(ANSI_COLOR_YELLOW "Block Hash cannot be empty.\n" ANSI_COLOR_RESET);
        return;
    }
    if (strlen(hash_buffer) != SHA256_HEX_LEN) {
        printf(ANSI_COLOR_RED "Invalid Block Hash length. Must be %d characters.\n" ANSI_COLOR_RESET, SHA256_HEX_LEN);
        return;
    }

    const Block* found_block = blockchain_get_block_by_hash(bc, hash_buffer);
    if (found_block != NULL) {
        printf(ANSI_COLOR_GREEN "Block Found:\n" ANSI_COLOR_RESET);
        if (g_cli_decryption_key_initialized) {
            block_print(found_block, g_cli_decryption_key);
        } else {
            logger_log(LOG_LEVEL_WARN, "Decryption key not initialized. Printing block without decrypting transaction data.");
            printf(ANSI_COLOR_YELLOW "Warning: Decryption key not available. Transaction data will be encrypted.\n" ANSI_COLOR_RESET);
            block_print(found_block, NULL);
        }
    } else {
        printf(ANSI_COLOR_RED "Block not found.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Block %s not found.", hash_buffer);
    }
}

/**
 * @brief Handles viewing a block by height interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_view_block_by_height_interactive(Blockchain* bc) {
    if (!bc) {
        printf(ANSI_COLOR_RED "No blockchain loaded. Create or load one first to view blocks.\n" ANSI_COLOR_RESET);
        return;
    }
    int height = get_int_input("Enter Block Height: ");
    if (height < 0) {
        printf(ANSI_COLOR_RED "Invalid block height. Must be non-negative.\n" ANSI_COLOR_RESET);
        return;
    }

    logger_log(LOG_LEVEL_INFO, "Searching for block at height %d...", height);
    const Block* found_block = blockchain_get_block_by_index(bc, (size_t)height);
    if (found_block) {
        // FIX: Added 'height' as a data argument for '%d'
        printf(ANSI_COLOR_GREEN "Block Found at Height %d:\n" ANSI_COLOR_RESET, height); 
        if (g_cli_decryption_key_initialized) {
            block_print(found_block, g_cli_decryption_key);
        } else {
            logger_log(LOG_LEVEL_WARN, "Decryption key not initialized. Printing block without decrypting transaction data.");
            printf(ANSI_COLOR_YELLOW "Warning: Decryption key not available. Transaction data will be encrypted.\n" ANSI_COLOR_RESET);
            block_print(found_block, NULL);
        }
    } else {
        printf(ANSI_COLOR_RED "Block not found at height %d.\n" ANSI_COLOR_RESET, height);
        logger_log(LOG_LEVEL_INFO, "Block not found at height %d.", height);
    }
}

/**
 * @brief Handles printing the mempool interactively.
 */
static void handle_print_mempool_interactive() {
    if (mempool_get_size() == 0) {
        printf(ANSI_COLOR_YELLOW "Mempool is empty. No pending transactions.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Mempool is empty, nothing to print.");
        return;
    }

    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "\n--- Pending Transactions in Mempool (%zu) ---\n" ANSI_COLOR_RESET, mempool_get_size());
    mempool_print();
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--- End of Mempool Print ---\n" ANSI_COLOR_RESET);
}

/**
 * @brief Handles setting the log level interactively.
 */
static void handle_set_log_level_interactive() {
    char level_str[20];
    printf(ANSI_COLOR_CYAN "Enter new log level (DEBUG, INFO, WARN, ERROR, FATAL, NONE): " ANSI_COLOR_RESET);
    get_string_input("", level_str, sizeof(level_str));

    to_lowercase(level_str);

    LogLevel new_level;
    if (strcmp(level_str, "debug") == 0) {
        new_level = LOG_LEVEL_DEBUG;
    } else if (strcmp(level_str, "info") == 0) {
        new_level = LOG_LEVEL_INFO;
    } else if (strcmp(level_str, "warn") == 0) {
        new_level = LOG_LEVEL_WARN;
    } else if (strcmp(level_str, "error") == 0) {
        new_level = LOG_LEVEL_ERROR;
    } else if (strcmp(level_str, "fatal") == 0) {
        new_level = LOG_LEVEL_FATAL;
    } else if (strcmp(level_str, "none") == 0) {
        new_level = LOG_LEVEL_NONE;
    } else {
        logger_log(LOG_LEVEL_WARN, "Unknown log level: '%s'. Keeping current level.", level_str);
        printf(ANSI_COLOR_RED "Unknown log level: '%s'. " ANSI_COLOR_RESET "Valid levels are " ANSI_COLOR_YELLOW "DEBUG, INFO, WARN, ERROR, FATAL, NONE" ANSI_COLOR_RESET ".\n", level_str);
        return;
    }
    logger_set_level(new_level);
    logger_log(LOG_LEVEL_INFO, "Log level set to %s.", level_str);
    printf(ANSI_COLOR_GREEN "Log level set to %s.\n" ANSI_COLOR_RESET, level_str);
}

/**
 * @brief Handles starting the network listener interactively.
 */
static void handle_start_listener_interactive() {
    char *port_str = strtok(NULL, " ");
    int port = DEFAULT_PORT;

    if (port_str != NULL) {
        port = atoi(port_str);
        if (port <= 0 || port > 65535) {
            printf(ANSI_COLOR_RED "Invalid port number. Please use a number between 1 and 65535.\n" ANSI_COLOR_RESET);
            logger_log(LOG_LEVEL_ERROR, "Invalid port number entered: %s", port_str);
            return;
        }
    }

    printf(ANSI_COLOR_CYAN "Attempting to start listener on port %d...\n" ANSI_COLOR_RESET, port);
    if (network_start_listener(port) == 0) {
        printf(ANSI_COLOR_GREEN "Network listener started successfully on port %d!\n" ANSI_COLOR_RESET, port);
        logger_log(LOG_LEVEL_INFO, "Network listener started on port %d.", port);
    } else {
        printf(ANSI_COLOR_RED "Failed to start network listener. %s\n" ANSI_COLOR_RESET, strerror(errno));
        logger_log(LOG_LEVEL_ERROR, "Failed to start network listener on port %d: %s", port, strerror(errno));
    }
}

/**
 * @brief Handles connecting to a peer interactively.
 */
static void handle_connect_peer_interactive() {
    char *ip_str = strtok(NULL, " ");
    char *port_str = strtok(NULL, " ");
    int port;

    if (ip_str == NULL || port_str == NULL) {
        printf(ANSI_COLOR_RED "Usage: connect-peer <ip> <port>\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Missing arguments for connect-peer command.");
        return;
    }

    port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        printf(ANSI_COLOR_RED "Invalid port number. Please use a number between 1 and 65535.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Invalid port number entered for connect-peer: %s", port_str);
        return;
    }

    printf(ANSI_COLOR_CYAN "Attempting to connect to peer %s:%d...\n" ANSI_COLOR_RESET, ip_str, port);
    if (network_connect_to_peer(ip_str, port) == 0) {
        printf(ANSI_COLOR_GREEN "Successfully initiated connection to peer %s:%d!\n" ANSI_COLOR_RESET, ip_str, port);
        logger_log(LOG_LEVEL_INFO, "Successfully initiated connection to peer %s:%d.", ip_str, port);
    } else {
        printf(ANSI_COLOR_RED "Failed to connect to peer %s:%d. %s\n" ANSI_COLOR_RESET, ip_str, port, strerror(errno));
        logger_log(LOG_LEVEL_ERROR, "Failed to connect to peer %s:%d: %s", ip_str, port, strerror(errno));
    }
}

/**
 * @brief Handles sending a test message interactively.
 */
static void handle_send_test_message_interactive() {
    char *message = strtok(NULL, ""); // Read the rest of the line as the message

    if (message == NULL || strlen(message) == 0) {
        printf(ANSI_COLOR_RED "Usage: send-test-message <message>\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Missing message for send-test-message command.");
        return;
    }

    while (*message == ' ') { // Remove leading space if strtok left one
        message++;
    }

    printf(ANSI_COLOR_CYAN "Sending test message to connected peers: \"%s\"\n" ANSI_COLOR_RESET, message);
    if (network_broadcast_data(MSG_TYPE_TEST_MESSAGE, (const uint8_t*)message, strlen(message) + 1) > 0) {
        printf(ANSI_COLOR_GREEN "Test message sent successfully to all connected peers.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Test message sent: \"%s\"", message);
    } else {
        printf(ANSI_COLOR_RED "Failed to send test message.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to send test message.");
    }
}

/**
 * @brief Handles broadcasting a transaction interactively.
 * @param bc Pointer to the blockchain.
 */
static void handle_broadcast_transaction_interactive(Blockchain* bc) {
    // NEW: Check for authenticated user
    if (strlen(g_current_username) == 0) {
        printf(ANSI_COLOR_RED "Error: You must be logged in to broadcast a transaction. Please 'login' or 'register'.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "Attempted broadcast-transaction without login.");
        return;
    }

    (void)bc; // Mark 'bc' as unused

    if (mempool_get_size() == 0) {
        printf(ANSI_COLOR_YELLOW "Mempool is empty. No transactions to broadcast.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Mempool is empty, cannot broadcast transaction.");
        return;
    }

    Transaction* tx_to_broadcast = mempool_get_first_transaction();

    if (tx_to_broadcast == NULL) {
        printf(ANSI_COLOR_RED "Failed to retrieve a transaction from mempool for broadcasting.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to retrieve transaction from mempool for broadcast.");
        return;
    }

    printf(ANSI_COLOR_CYAN "Broadcasting transaction %s to connected peers...\n" ANSI_COLOR_RESET, tx_to_broadcast->transaction_id);

    size_t serialized_len = 0;
    uint8_t* serialized_tx = transaction_serialize(tx_to_broadcast, &serialized_len);

    if (serialized_tx == NULL || serialized_len == 0) {
        printf(ANSI_COLOR_RED "Failed to serialize transaction for broadcasting.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to serialize transaction %s for broadcast.", tx_to_broadcast->transaction_id);
        return;
    }

    if (network_broadcast_data(MSG_TYPE_TRANSACTION, serialized_tx, serialized_len) > 0) {
        printf(ANSI_COLOR_GREEN "Transaction broadcast successful!\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Transaction %s broadcast successfully.", tx_to_broadcast->transaction_id);
    } else {
        printf(ANSI_COLOR_RED "Failed to broadcast transaction (no active peers or network error).\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to broadcast transaction %s (no peers or network error).", tx_to_broadcast->transaction_id);
    }

    free(serialized_tx);
}


// --- NEW: Authentication Handlers ---

/**
 * @brief Handles user registration interactively.
 */
static void handle_register_user_interactive() {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_INPUT_LEN];
    char confirm_password[MAX_PASSWORD_INPUT_LEN];
    User new_user;

    get_string_input("Enter desired username: ", username, sizeof(username));
    if (strlen(username) == 0) {
        printf(ANSI_COLOR_YELLOW "Username cannot be empty.\n" ANSI_COLOR_RESET);
        return;
    }
    strncpy(new_user.username, username, sizeof(new_user.username) - 1);
    new_user.username[sizeof(new_user.username) - 1] = '\0';

    get_password_input("Enter password: ", password, sizeof(password));
    if (strlen(password) == 0) {
        printf(ANSI_COLOR_YELLOW "Password cannot be empty.\n" ANSI_COLOR_RESET);
        return;
    }
    get_password_input("Confirm password: ", confirm_password, sizeof(confirm_password));

    if (strcmp(password, confirm_password) != 0) {
        printf(ANSI_COLOR_RED "Passwords do not match. User registration failed.\n" ANSI_COLOR_RESET);
        return;
    }

    // Hash the password
    uint8_t hashed_password_binary[SHA256_DIGEST_LENGTH];
    if (hasher_sha256((const uint8_t*)password, strlen(password), hashed_password_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash password for new user.");
        printf(ANSI_COLOR_RED "Failed to hash password. Registration failed.\n" ANSI_COLOR_RESET);
        return;
    }
    hasher_bytes_to_hex_buf(hashed_password_binary, SHA256_DIGEST_LENGTH, new_user.hashed_password, sizeof(new_user.hashed_password));

    printf(ANSI_COLOR_CYAN "Generating new ECDSA key pair for '%s'...\n" ANSI_COLOR_RESET, new_user.username);
    if (key_management_generate_key_pair(new_user.private_key_pem, new_user.public_key_pem, sizeof(new_user.private_key_pem)) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate key pair for new user '%s'.", new_user.username);
        printf(ANSI_COLOR_RED "Failed to generate key pair. Registration failed.\n" ANSI_COLOR_RESET);
        return;
    }
    if (key_management_derive_public_key_hash(new_user.public_key_pem, new_user.public_key_hash, sizeof(new_user.public_key_hash)) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to derive public key hash for new user '%s'.", new_user.username);
        printf(ANSI_COLOR_RED "Failed to derive public key hash. Registration failed.\n" ANSI_COLOR_RESET);
        return;
    }

    if (user_store_add_user(&new_user) == 0) {
        logger_log(LOG_LEVEL_INFO, "User '%s' registered successfully.", new_user.username);
        printf(ANSI_COLOR_GREEN "User '%s' registered successfully! You can now 'login'.\n" ANSI_COLOR_RESET, new_user.username);
    } else {
        printf(ANSI_COLOR_RED "Failed to register user '%s'. (Username might already exist).\n" ANSI_COLOR_RESET, new_user.username);
    }
}

/**
 * @brief Handles user login interactively.
 */
static void handle_login_user_interactive() {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_INPUT_LEN];
    User found_user;

    if (strlen(g_current_username) > 0) {
        printf(ANSI_COLOR_YELLOW "User '%s' is already logged in. Please 'logout' first.\n" ANSI_COLOR_RESET, g_current_username);
        return;
    }

    get_string_input("Enter username: ", username, sizeof(username));
    if (strlen(username) == 0) {
        printf(ANSI_COLOR_YELLOW "Username cannot be empty.\n" ANSI_COLOR_RESET);
        return;
    }

    get_password_input("Enter password: ", password, sizeof(password));
    if (strlen(password) == 0) {
        printf(ANSI_COLOR_YELLOW "Password cannot be empty.\n" ANSI_COLOR_RESET);
        return;
    }

    if (user_store_find_user(username, &found_user) != 0) {
        printf(ANSI_COLOR_RED "Login failed: User '%s' not found.\n" ANSI_COLOR_RESET, username);
        logger_log(LOG_LEVEL_WARN, "Login failed for '%s': User not found.", username);
        return;
    }

    // Hash provided password for comparison
    uint8_t entered_hashed_password_binary[SHA256_DIGEST_LENGTH];
    char entered_hashed_password_hex[SHA256_HEX_LEN + 1];
    if (hasher_sha256((const uint8_t*)password, strlen(password), entered_hashed_password_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash entered password for login.");
        printf(ANSI_COLOR_RED "Internal Error: Failed to process password.\n" ANSI_COLOR_RESET);
        return;
    }
    hasher_bytes_to_hex_buf(entered_hashed_password_binary, SHA256_DIGEST_LENGTH, entered_hashed_password_hex, sizeof(entered_hashed_password_hex));

    if (strcmp(found_user.hashed_password, entered_hashed_password_hex) == 0) {
        // Successful login! Load user's keys into global CLI variables
        strncpy(g_cli_private_key_pem, found_user.private_key_pem, sizeof(g_cli_private_key_pem) - 1);
        g_cli_private_key_pem[sizeof(g_cli_private_key_pem) - 1] = '\0';

        strncpy(g_cli_public_key_pem, found_user.public_key_pem, sizeof(g_cli_public_key_pem) - 1);
        g_cli_public_key_pem[sizeof(g_cli_public_key_pem) - 1] = '\0';

        strncpy(g_cli_public_key_hash, found_user.public_key_hash, sizeof(g_cli_public_key_hash) - 1);
        g_cli_public_key_hash[sizeof(g_cli_public_key_hash) - 1] = '\0';

        strncpy(g_current_username, found_user.username, sizeof(g_current_username) - 1);
        g_current_username[sizeof(g_current_username) - 1] = '\0';

        logger_log(LOG_LEVEL_INFO, "User '%s' logged in successfully. Wallet hash: %s", g_current_username, g_cli_public_key_hash);
        printf(ANSI_COLOR_GREEN "Welcome, %s! Your wallet (%s...) is now active.\n" ANSI_COLOR_RESET, g_current_username, g_cli_public_key_hash);
    } else {
        logger_log(LOG_LEVEL_WARN, "Login failed for '%s': Incorrect password.", username);
        printf(ANSI_COLOR_RED "Login failed: Incorrect password.\n" ANSI_COLOR_RESET);
    }
}

/**
 * @brief Handles user logout interactively.
 */
static void handle_logout_user_interactive() {
    if (strlen(g_current_username) == 0) {
        printf(ANSI_COLOR_YELLOW "No user is currently logged in.\n" ANSI_COLOR_RESET);
        return;
    }

    logger_log(LOG_LEVEL_INFO, "User '%s' logged out.", g_current_username);
    printf(ANSI_COLOR_GREEN "User '%s' logged out successfully.\n" ANSI_COLOR_RESET, g_current_username);

    // Clear active user data
    g_cli_private_key_pem[0] = '\0';
    g_cli_public_key_pem[0] = '\0';
    g_cli_public_key_hash[0] = '\0';
    g_current_username[0] = '\0';
}

