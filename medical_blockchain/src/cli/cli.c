// src/cli/cli.c
#include "cli/cli.h"
#include "utils/logger.h"
#include "utils/colors.h"
#include "core/blockchain.h"
#include "core/block.h"
#include "core/transaction.h"
#include "security/encryption.h"
#include "config/config.h"
#include "storage/disk_storage.h"
#include "network/network.h" // <--- NEW: Include network header

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h> // For ctime in print_chain

// Forward declarations for internal CLI commands
static void print_help_menu();
static void handle_create_blockchain_interactive(Blockchain** bc);
static void handle_add_transaction_interactive(Blockchain* bc);
static void handle_mine_block_interactive(Blockchain* bc);
static void handle_validate_chain_interactive(Blockchain* bc);
static void handle_print_chain_interactive(Blockchain* bc, const uint8_t* encryption_key);
static void handle_set_log_level_interactive();
static void handle_save_blockchain_interactive(Blockchain* bc, const char* blockchain_file_path);
static void handle_load_blockchain_interactive(Blockchain** bc, const char* blockchain_file_path);

// NEW: Network command handlers
static void handle_start_listener_interactive(void);
static void handle_connect_peer_interactive(void);
static void handle_send_test_message_interactive(void); // Simple message sending for testing


// A dummy encryption key for demonstration purposes.
static uint8_t g_dummy_encryption_key[AES_256_KEY_SIZE];
static int g_key_initialized = 0;
static Blockchain* g_current_blockchain = NULL;
static const char* g_blockchain_file_path = DEFAULT_DATA_DIR "/" DEFAULT_BLOCKCHAIN_FILE;

// Helper to convert string to lowercase
static void to_lowercase(char* str) {
    for (char *p = str; *p; p++) {
        *p = tolower(*p);
    }
}

int cli_run() {
    if (logger_init("blockchain_cli.log") != 0) {
        fprintf(stderr, ANSI_COLOR_RED "Failed to initialize logger.\n" ANSI_COLOR_RESET);
        return 1;
    }
    logger_set_level(LOG_LEVEL_INFO);

    logger_log(LOG_LEVEL_INFO, "Blockchain CLI started (interactive mode).");

    // NEW: Initialize network module
    if (network_init() != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to initialize network module. Exiting.");
        logger_shutdown();
        return EXIT_FAILURE;
    }

    if (!g_key_initialized) {
        if (encryption_generate_random_bytes(g_dummy_encryption_key, AES_256_KEY_SIZE) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to generate dummy encryption key for CLI.");
            network_shutdown(); // Shutdown network if init fails
            logger_shutdown();
            return 1;
        }
        g_key_initialized = 1;
        logger_log(LOG_LEVEL_DEBUG, "Dummy encryption key initialized.");
    }

    if (disk_storage_ensure_dir(DEFAULT_DATA_DIR) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create blockchain data directory: %s. Exiting.", DEFAULT_DATA_DIR);
        network_shutdown(); // Shutdown network if init fails
        logger_shutdown();
        return EXIT_FAILURE;
    }

    char command[256];
    int running = 1;

    // Enhanced welcome message
    printf(ANSI_COLOR_CYAN ANSI_STYLE_BOLD "\n==============================================\n");
    printf("  Welcome to the Medical Blockchain CLI!\n");
    printf("==============================================\n" ANSI_COLOR_RESET);
    printf("Type " ANSI_COLOR_YELLOW "'help'" ANSI_COLOR_RESET " for a list of commands, or " ANSI_COLOR_YELLOW "'exit'" ANSI_COLOR_RESET " to quit.\n");

    while (running) {
        printf(ANSI_COLOR_BLUE "\nBlockchain CLI > " ANSI_COLOR_RESET);
        if (fgets(command, sizeof(command), stdin) == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Error reading input or EOF reached.");
            break;
        }
        command[strcspn(command, "\n")] = 0;

        char *token = strtok(command, " ");
        if (token == NULL) {
            continue;
        }

        to_lowercase(token);

        if (strcmp(token, "help") == 0) {
            print_help_menu();
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
                handle_print_chain_interactive(g_current_blockchain, g_dummy_encryption_key);
            } else {
                handle_print_chain_interactive(g_current_blockchain, NULL);
            }
        } else if (strcmp(token, "set-log-level") == 0) {
            handle_set_log_level_interactive();
        }
        // NEW: Network Commands
        else if (strcmp(token, "start-listener") == 0) {
            handle_start_listener_interactive();
        } else if (strcmp(token, "connect-peer") == 0) {
            handle_connect_peer_interactive();
        } else if (strcmp(token, "send-test-message") == 0) {
            handle_send_test_message_interactive();
        }
        // End NEW Network Commands
        else if (strcmp(token, "exit") == 0 || strcmp(token, "quit") == 0) {
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
    network_shutdown(); // NEW: Shutdown network module
    logger_shutdown();
    return 0;
}

static void print_help_menu() {
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "\n--- Available Commands ---\n" ANSI_COLOR_RESET);
    printf("  " ANSI_COLOR_YELLOW "help" ANSI_COLOR_RESET "                         : Display this help menu.\n");
    printf("  " ANSI_COLOR_GREEN "create-blockchain" ANSI_COLOR_RESET "          : Creates a new blockchain with a genesis block (overwrites if exists).\n");
    printf("  " ANSI_COLOR_GREEN "load-blockchain" ANSI_COLOR_RESET "            : Loads an existing blockchain from disk.\n");
    printf("  " ANSI_COLOR_GREEN "save-blockchain" ANSI_COLOR_RESET "            : Saves the current blockchain to disk.\n");
    printf("  " ANSI_COLOR_GREEN "add-transaction" ANSI_COLOR_RESET "            : Adds a placeholder transaction to pending transactions.\n");
    printf("  " ANSI_COLOR_GREEN "mine-block" ANSI_COLOR_RESET "                   : Mines a new block with pending transactions.\n");
    printf("  " ANSI_COLOR_GREEN "validate-chain" ANSI_COLOR_RESET "             : Validates the integrity of the blockchain.\n");
    printf("  " ANSI_COLOR_GREEN "print-chain" ANSI_COLOR_RESET " [" ANSI_COLOR_YELLOW "--decrypt" ANSI_COLOR_RESET "]      : Prints all blocks. Use --decrypt to attempt medical data decryption.\n");
    printf("  " ANSI_COLOR_CYAN "set-log-level" ANSI_COLOR_RESET "              : Set the logger level (DEBUG, INFO, WARN, ERROR, FATAL, NONE).\n");
    // NEW Network Commands
    printf("  " ANSI_COLOR_BLUE "start-listener <port>" ANSI_COLOR_RESET "      : Starts listening for incoming connections on a port.\n");
    printf("  " ANSI_COLOR_BLUE "connect-peer <ip> <port>" ANSI_COLOR_RESET ": Connects to a remote blockchain peer.\n");
    printf("  " ANSI_COLOR_BLUE "send-test-message <msg>" ANSI_COLOR_RESET ": Sends a test message to all connected peers.\n");
    // End NEW Network Commands
    printf("  " ANSI_COLOR_RED "exit | quit" ANSI_COLOR_RESET "                : Exits the CLI application.\n");
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--------------------------\n" ANSI_COLOR_RESET);
}

// Interactive handlers (adapted from previous handle_* functions)
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

static void handle_add_transaction_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot add transaction.");
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. " ANSI_COLOR_RESET "Use " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'load-blockchain'" ANSI_COLOR_RESET " first.\n");
        return;
    }

    const char* sender = "cli_sender";
    const char* recipient = "cli_recipient";
    const char* medical_data = "{\"patient\":\"CLI-Patient\", \"diagnosis\":\"Interactive_Flu_Vaccine\"}";
    double value = 5.5;

    printf(ANSI_COLOR_CYAN "Adding a sample transaction...\n" ANSI_COLOR_RESET);
    Transaction* tx = transaction_create(sender, recipient, medical_data, value, g_dummy_encryption_key);

    if (tx) {
        transaction_sign(tx, "CLI_PrivateKey_For_Signing_Tx");
        logger_log(LOG_LEVEL_INFO, "Sample transaction created.");
        if (blockchain_add_transaction_to_pending(bc, tx) != 0) {
            logger_log(LOG_LEVEL_ERROR, "Failed to add transaction to pending list.");
            printf(ANSI_COLOR_RED "Failed to add transaction to pending list.\n" ANSI_COLOR_RESET);
            transaction_destroy(tx);
        } else {
            logger_log(LOG_LEVEL_INFO, "Transaction added to pending list. Mine a block to include it!");
            printf(ANSI_COLOR_GREEN "Transaction added to pending list. " ANSI_COLOR_RESET "Remember to " ANSI_COLOR_YELLOW "'mine-block'" ANSI_COLOR_RESET " to include it in the chain.\n");
        }
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create sample transaction.");
        printf(ANSI_COLOR_RED "Failed to create sample transaction.\n" ANSI_COLOR_RESET);
    }
}

static void handle_mine_block_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot mine block.");
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. " ANSI_COLOR_RESET "Use " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'load-blockchain'" ANSI_COLOR_RESET " first.\n");
        return;
    }
    printf(ANSI_COLOR_CYAN "Attempting to mine a new block...\n" ANSI_COLOR_RESET);
    if (blockchain_mine_new_block(bc) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to mine a new block.");
        printf(ANSI_COLOR_RED "Failed to mine a new block. " ANSI_COLOR_RESET "(Perhaps no pending transactions or an issue with Proof-of-Work?)\n");
    } else {
        logger_log(LOG_LEVEL_INFO, "New block mined successfully!");
        printf(ANSI_COLOR_GREEN "New block mined and added to the chain!\n" ANSI_COLOR_RESET);
        printf("Current chain length: " ANSI_COLOR_YELLOW "%zu\n" ANSI_COLOR_RESET, bc->length);
    }
}

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
            block_print(b, encryption_key); // block_print will use colors internally
            printf(ANSI_COLOR_CYAN "-----------------\n" ANSI_COLOR_RESET);
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to retrieve block at index %zu for printing.", i);
        }
    }
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--- End of Blockchain Print ---\n" ANSI_COLOR_RESET);
}

static void handle_set_log_level_interactive() {
    char level_str[20];
    printf(ANSI_COLOR_CYAN "Enter new log level (DEBUG, INFO, WARN, ERROR, FATAL, NONE): " ANSI_COLOR_RESET);
    if (fgets(level_str, sizeof(level_str), stdin) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error reading log level input.");
        printf(ANSI_COLOR_RED "Failed to read log level.\n" ANSI_COLOR_RESET);
        return;
    }
    level_str[strcspn(level_str, "\n")] = 0;

    to_lowercase(level_str);

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
        printf(ANSI_COLOR_RED "Unknown log level: '%s'. " ANSI_COLOR_RESET "Valid levels are " ANSI_COLOR_YELLOW "DEBUG, INFO, WARN, ERROR, FATAL, NONE" ANSI_COLOR_RESET ".\n", level_str);
        return;
    }
    logger_log(LOG_LEVEL_INFO, "Log level set to %s.", level_str);
    printf(ANSI_COLOR_GREEN "Log level set to %s.\n" ANSI_COLOR_RESET, level_str);
}

// --- NEW: Network Command Handlers ---

static void handle_start_listener_interactive() {
    char *port_str = strtok(NULL, " ");
    int port = DEFAULT_PORT; // Use default if no port specified

    if (port_str != NULL) {
        port = atoi(port_str);
        if (port <= 0 || port > 65535) {
            printf(ANSI_COLOR_RED "Invalid port number. Please use a number between 1 and 65535.\n" ANSI_COLOR_RESET);
            logger_log(LOG_LEVEL_ERROR, "Invalid port number entered: %s", port_str);
            return;
        }
    }

    printf(ANSI_COLOR_CYAN "Attempting to start listener on port %d...\n" ANSI_COLOR_RESET, port);
    if (network_start_listener(port) != 0) {
        printf(ANSI_COLOR_RED "Failed to start network listener.\n" ANSI_COLOR_RESET);
    } else {
        // Updated message to reflect that the CLI remains responsive due to threading.
        printf(ANSI_COLOR_GREEN "Network listener started successfully in the background!\n" ANSI_COLOR_RESET);
        printf("You can now continue using the CLI or connect from another node.\n");
    }
}

static void handle_connect_peer_interactive() {
    char *ip_address = strtok(NULL, " ");
    char *port_str = strtok(NULL, " ");

    if (ip_address == NULL || port_str == NULL) {
        printf(ANSI_COLOR_RED "Usage: connect-peer <ip_address> <port>\n" ANSI_COLOR_RESET);
        return;
    }

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        printf(ANSI_COLOR_RED "Invalid port number. Please use a number between 1 and 65535.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Invalid port number entered for connect-peer: %s", port_str);
        return;
    }

    printf(ANSI_COLOR_CYAN "Attempting to connect to peer %s:%d...\n" ANSI_COLOR_RESET, ip_address, port);
    network_connect_to_peer(ip_address, port);
}

static void handle_send_test_message_interactive() {
    // Read the rest of the line as the message
    char *message_content = strtok(NULL, "");

    if (message_content == NULL || strlen(message_content) == 0) {
        printf(ANSI_COLOR_RED "Usage: send-test-message <your_message_here>\n" ANSI_COLOR_RESET);
        return;
    }

    // Trim leading space if any (strtok with "" might leave it)
    while (*message_content == ' ') {
        message_content++;
    }

    int peer_fd = network_get_first_peer_socket_fd(); // Get the FD of the first connected peer
    if (peer_fd == -1) {
        printf(ANSI_COLOR_YELLOW "No active peers to send messages to. Use 'connect-peer' first.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "No active peers to send test message.");
        return;
    }

    printf(ANSI_COLOR_CYAN "Sending test message to peer (FD: %d): \"%s\"\n" ANSI_COLOR_RESET, peer_fd, message_content);
    ssize_t sent_bytes = network_send_message(peer_fd, (const uint8_t*)message_content, strlen(message_content));

    if (sent_bytes > 0) {
        printf(ANSI_COLOR_GREEN "Message sent successfully (%zd bytes).\n" ANSI_COLOR_RESET, sent_bytes);
    } else if (sent_bytes == 0) {
        printf(ANSI_COLOR_YELLOW "No bytes sent (message might be empty).\n" ANSI_COLOR_RESET);
    } else {
        printf(ANSI_COLOR_RED "Failed to send message.\n" ANSI_COLOR_RESET);
    }
}
