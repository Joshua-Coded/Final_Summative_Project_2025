// src/cli/cli.c
#include "cli/cli.h"
#include "utils/logger.h"
#include "core/blockchain.h"
#include "core/block.h"        // Might need for block_print
#include "core/transaction.h"  // Might need for creating transactions
#include "security/encryption.h" // For encryption_generate_random_bytes and AES_256_KEY_SIZE
#include "config/config.h"            // For DEFAULT_DIFFICULTY and PENDING_TRANSACTIONS_INITIAL_CAPACITY (if not already in block.h or blockchain.h)
#include "storage/disk_storage.h" // For loading/saving blockchain

#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For atoi, exit, malloc, free
#include <ctype.h>  // For tolower

// Forward declarations for internal CLI commands
static void print_help_menu();
// Removed blockchain_file_path parameter from handle_create_blockchain_interactive
static void handle_create_blockchain_interactive(Blockchain** bc);
static void handle_add_transaction_interactive(Blockchain* bc);
static void handle_mine_block_interactive(Blockchain* bc);
static void handle_validate_chain_interactive(Blockchain* bc);
static void handle_print_chain_interactive(Blockchain* bc, const uint8_t* encryption_key);
static void handle_set_log_level_interactive();
static void handle_save_blockchain_interactive(Blockchain* bc, const char* blockchain_file_path);
static void handle_load_blockchain_interactive(Blockchain** bc, const char* blockchain_file_path);

// A dummy encryption key for demonstration purposes.
// In a real application, this would be securely managed (e.g., loaded from a file, user input, HSM).
static uint8_t g_dummy_encryption_key[AES_256_KEY_SIZE];
static int g_key_initialized = 0;
static Blockchain* g_current_blockchain = NULL; // Global blockchain pointer for the interactive session
static const char* g_blockchain_file_path = DEFAULT_DATA_DIR "/" DEFAULT_BLOCKCHAIN_FILE;


// Helper to convert string to lowercase
static void to_lowercase(char* str) {
    for (char *p = str; *p; p++) {
        *p = tolower(*p);
    }
}

int cli_run() { // No longer takes argc, argv
    // Initialize logger first
    if (logger_init("blockchain_cli.log") != 0) {
        fprintf(stderr, "Failed to initialize logger.\n");
        return 1;
    }
    logger_set_level(LOG_LEVEL_INFO); // Default CLI log level

    logger_log(LOG_LEVEL_INFO, "Blockchain CLI started (interactive mode).");

    // Initialize the dummy key once
    if (!g_key_initialized) {
        if (encryption_generate_random_bytes(g_dummy_encryption_key, AES_256_KEY_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to generate dummy encryption key for CLI.");
            logger_shutdown();
            return 1;
        }
        g_key_initialized = 1;
        logger_log(LOG_LEVEL_DEBUG, "Dummy encryption key initialized.");
    }

    // Ensure data directory exists
    if (disk_storage_ensure_dir(DEFAULT_DATA_DIR) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create blockchain data directory: %s. Exiting.", DEFAULT_DATA_DIR);
        logger_shutdown();
        return EXIT_FAILURE;
    }

    char command[256];
    int running = 1;

    printf("\nWelcome to the Blockchain Medical Records CLI (Interactive Mode)!\n");
    printf("Type 'help' for a list of commands, or 'exit' to quit.\n");

    while (running) {
        printf("\nBlockchain CLI > ");
        if (fgets(command, sizeof(command), stdin) == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Error reading input or EOF reached.");
            break;
        }
        command[strcspn(command, "\n")] = 0; // Remove newline character

        char *token = strtok(command, " ");
        if (token == NULL) {
            continue; // Empty input
        }

        to_lowercase(token); // Convert command to lowercase for case-insensitivity

        if (strcmp(token, "help") == 0) {
            print_help_menu();
        } else if (strcmp(token, "create-blockchain") == 0) {
            // Pass g_blockchain_file_path here if it were needed by the function itself
            // but since it's global, we can remove the parameter.
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
                handle_print_chain_interactive(g_current_blockchain, g_dummy_encryption_key);
            } else {
                handle_print_chain_interactive(g_current_blockchain, NULL);
            }
        } else if (strcmp(token, "set-log-level") == 0) {
            handle_set_log_level_interactive();
        } else if (strcmp(token, "exit") == 0 || strcmp(token, "quit") == 0) {
            running = 0;
            logger_log(LOG_LEVEL_INFO, "Exiting CLI.");
        } else {
            logger_log(LOG_LEVEL_WARN, "Unknown command: '%s'. Type 'help' for options.", token);
        }
    }

    // Clean up global blockchain
    if (g_current_blockchain) {
        blockchain_destroy(g_current_blockchain);
        g_current_blockchain = NULL;
    }
    logger_shutdown();
    return 0;
}

static void print_help_menu() {
    printf("\nAvailable Commands:\n");
    printf("  help                         : Display this help menu.\n");
    printf("  create-blockchain            : Creates a new blockchain with a genesis block (overwrites if exists).\n");
    printf("  load-blockchain              : Loads an existing blockchain from disk.\n");
    printf("  save-blockchain              : Saves the current blockchain to disk.\n");
    printf("  add-transaction              : Adds a placeholder transaction to pending transactions.\n");
    printf("  mine-block                   : Mines a new block with pending transactions.\n");
    printf("  validate-chain               : Validates the integrity of the blockchain.\n");
    printf("  print-chain [--decrypt]      : Prints all blocks. Use --decrypt to attempt medical data decryption.\n");
    printf("  set-log-level                : Set the logger level (DEBUG, INFO, WARN, ERROR, FATAL, NONE).\n");
    printf("  exit | quit                  : Exits the CLI application.\n");
}

// Interactive handlers (adapted from previous handle_* functions)
// Removed blockchain_file_path parameter from function definition
static void handle_create_blockchain_interactive(Blockchain** bc) {
    if (*bc != NULL) {
        logger_log(LOG_LEVEL_WARN, "Blockchain already exists in memory. Destroying and recreating.");
        blockchain_destroy(*bc);
        *bc = NULL;
    }
    *bc = blockchain_create();
    if (*bc) {
        logger_log(LOG_LEVEL_INFO, "Blockchain created successfully with a genesis block.");
        printf("New blockchain created. Remember to 'save-blockchain' to persist it.\n");
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create blockchain.");
        printf("Failed to create blockchain.\n");
    }
}

static void handle_load_blockchain_interactive(Blockchain** bc, const char* blockchain_file_path) {
    if (*bc != NULL) {
        logger_log(LOG_LEVEL_WARN, "A blockchain is already loaded. Discarding in-memory chain before loading.");
        blockchain_destroy(*bc);
        *bc = NULL;
    }

    *bc = disk_storage_load_blockchain(blockchain_file_path);
    if (*bc) {
        logger_log(LOG_LEVEL_INFO, "Blockchain loaded successfully from '%s' (length: %zu).", blockchain_file_path, (*bc)->length);
        printf("Blockchain loaded successfully. Current chain length: %zu\n", (*bc)->length);
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to load blockchain from '%s'. It might not exist.", blockchain_file_path);
        printf("Failed to load blockchain. It might not exist or is corrupted. Try 'create-blockchain'.\n");
    }
}

static void handle_save_blockchain_interactive(Blockchain* bc, const char* blockchain_file_path) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "No blockchain in memory to save.");
        printf("No blockchain is currently loaded in memory to save. Use 'create-blockchain' or 'load-blockchain' first.\n");
        return;
    }
    if (disk_storage_save_blockchain(bc, blockchain_file_path) == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain saved successfully to '%s'.", blockchain_file_path);
        printf("Blockchain saved successfully.\n");
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to save blockchain to '%s'.", blockchain_file_path);
        printf("Failed to save blockchain. Check logs for details.\n");
    }
}

static void handle_add_transaction_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot add transaction.");
        printf("Blockchain not created or loaded. Use 'create-blockchain' or 'load-blockchain' first.\n");
        return;
    }

    // Example fixed values for now; could extend to prompt user for input
    const char* sender = "cli_sender";
    const char* recipient = "cli_recipient";
    const char* medical_data = "{\"patient\":\"CLI-Patient\", \"diagnosis\":\"Interactive_Flu_Vaccine\"}";
    double value = 5.5;

    printf("Adding a sample transaction...\n");
    Transaction* tx = transaction_create(sender, recipient, medical_data, value, g_dummy_encryption_key);

    if (tx) {
        // Basic signing (placeholder)
        transaction_sign(tx, "CLI_PrivateKey_For_Signing_Tx");

        logger_log(LOG_LEVEL_INFO, "Sample transaction created.");
        if (blockchain_add_transaction_to_pending(bc, tx) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to add transaction to pending list.");
            printf("Failed to add transaction to pending list.\n");
            transaction_destroy(tx);
        } else {
            logger_log(LOG_LEVEL_INFO, "Transaction added to pending list. Mine a block to include it!");
            printf("Transaction added to pending list. Remember to 'mine-block' to include it in the chain.\n");
        }
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create sample transaction.");
        printf("Failed to create sample transaction.\n");
    }
}

static void handle_mine_block_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot mine block.");
        printf("Blockchain not created or loaded. Use 'create-blockchain' or 'load-blockchain' first.\n");
        return;
    }
    if (blockchain_mine_new_block(bc) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to mine a new block.");
        printf("Failed to mine a new block. Check logs for details. (Perhaps no pending transactions?)\n");
    } else {
        logger_log(LOG_LEVEL_INFO, "New block mined successfully!");
        printf("New block mined and added to the chain!\n");
        printf("Current chain length: %zu\n", bc->length);
    }
}

static void handle_validate_chain_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Nothing to validate.");
        printf("Blockchain not created or loaded. Nothing to validate.\n");
        return;
    }
    printf("Validating blockchain...\n");
    if (blockchain_is_valid(bc) == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain is valid.");
        printf("Blockchain is VALID!\n");
    } else {
        logger_log(LOG_LEVEL_ERROR, "Blockchain is INVALID!");
        printf("Blockchain is INVALID! Check logs for details on potential tampering.\n");
    }
}

static void handle_print_chain_interactive(Blockchain* bc, const uint8_t* encryption_key) {
    if (bc == NULL || bc->length == 0) {
        logger_log(LOG_LEVEL_INFO, "Blockchain is empty, nothing to print.");
        printf("Blockchain is empty, nothing to print.\n");
        return;
    }
    printf("\n--- Printing Blockchain (Length: %zu) ---\n", bc->length);
    for (size_t i = 0; i < bc->length; ++i) {
        Block* b = blockchain_get_block_by_index(bc, i);
        if (b) {
            // block_print now handles decryption based on 'encryption_key'
            block_print(b, encryption_key);
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to retrieve block at index %zu for printing.", i);
        }
    }
    printf("--- End of Blockchain Print ---\n");
}

static void handle_set_log_level_interactive() {
    char level_str[20];
    printf("Enter new log level (DEBUG, INFO, WARN, ERROR, FATAL, NONE): ");
    if (fgets(level_str, sizeof(level_str), stdin) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error reading log level input.");
        printf("Failed to read log level.\n");
        return;
    }
    level_str[strcspn(level_str, "\n")] = 0; // Remove newline

    to_lowercase(level_str); // Convert input to lowercase

    if (strcmp(level_str, "debug") == 0) {
        logger_set_level(LOG_LEVEL_DEBUG);
    } else if (strcmp(level_str, "info") == 0) {
        logger_set_level(LOG_LEVEL_INFO);
    } else if (strcmp(level_str, "warn") == 0) {
        logger_set_level(LOG_LEVEL_WARN);
    } else if (strcmp(level_str, "error") == 0) {
        logger_set_level(LOG_LEVEL_ERROR);
    } else if (strcmp(level_str, "fatal") == 0) {
        logger_set_level(LOG_LEVEL_FATAL);
    } else if (strcmp(level_str, "none") == 0) {
        logger_set_level(LOG_LEVEL_NONE);
    } else {
        logger_log(LOG_LEVEL_WARN, "Unknown log level: '%s'. Keeping current level.", level_str);
        printf("Unknown log level: '%s'. Valid levels are DEBUG, INFO, WARN, ERROR, FATAL, NONE.\n", level_str);
        return;
    }
    logger_log(LOG_LEVEL_INFO, "Log level set to %s.", level_str);
    printf("Log level set to %s.\n", level_str);
}
// Add a newline character at the very end of the file
