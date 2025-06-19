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
#include "storage/disk_storage.h"
#include "network/network.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h> // <--- Include for perror and errno

static Blockchain* g_current_blockchain = NULL;
static char g_blockchain_file_path[256];

static char g_cli_private_key_pem[4096] = {0};
static char g_cli_public_key_pem[4096] = {0};
static char g_cli_public_key_hash[SHA256_HEX_LEN + 1] = {0};

static uint8_t g_cli_decryption_key[AES_256_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};
static int g_cli_decryption_key_initialized = 0;

static void to_lowercase(char* str);
static void get_string_input(const char* prompt, char* buffer, size_t buffer_size);
static int get_int_input(const char* prompt);
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
static void handle_send_test_message_interactive();
static void handle_generate_keys_interactive();
static void handle_broadcast_transaction_interactive(Blockchain* bc);

static void to_lowercase(char* str) {
    for (char *p = str; *p; p++) {
        *p = tolower(*p);
    }
}

static void get_string_input(const char* prompt, char* buffer, size_t buffer_size) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Error reading input or EOF reached.");
        buffer[0] = '\0';
    }
    buffer[strcspn(buffer, "\n")] = 0;
}

static int get_int_input(const char* prompt) {
    char buffer[256];
    get_string_input(prompt, buffer, sizeof(buffer));
    return atoi(buffer);
}

int cli_run() {
    if (logger_init("blockchain_cli.log") != 0) {
        fprintf(stderr, ANSI_COLOR_RED "Failed to initialize logger.\n" ANSI_COLOR_RESET);
        return 1;
    }
    logger_set_level(LOG_LEVEL_INFO);

    logger_log(LOG_LEVEL_INFO, "Blockchain CLI started (interactive mode).");

    snprintf(g_blockchain_file_path, sizeof(g_blockchain_file_path), "%s/%s", DEFAULT_DATA_DIR, DEFAULT_BLOCKCHAIN_FILENAME);

    if (network_init() != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to initialize network module. Exiting.");
        logger_shutdown();
        return EXIT_FAILURE;
    }

    g_cli_decryption_key_initialized = 1;

    if (disk_storage_ensure_dir(DEFAULT_DATA_DIR) != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create blockchain data directory: %s. Exiting.", DEFAULT_DATA_DIR);
        network_shutdown();
        logger_shutdown();
        return EXIT_FAILURE;
    }

    // Ensure the key storage directories exist at startup
    if (disk_storage_ensure_dir("data/keys") != 0 ||
        disk_storage_ensure_dir("data/keys/private_keys") != 0 ||
        disk_storage_ensure_dir("data/keys/public_keys") != 0) {
        logger_log(LOG_LEVEL_FATAL, "Failed to create key storage directories. Exiting.");
        network_shutdown();
        logger_shutdown();
        return EXIT_FAILURE;
    }


    mempool_init();

    if (strlen(g_cli_private_key_pem) == 0) {
        logger_log(LOG_LEVEL_INFO, "Auto-generating initial ECDSA key pair for CLI session...");
        // Auto-generation is for session only, not file saving
        if (key_management_generate_key_pair(g_cli_private_key_pem, g_cli_public_key_pem, sizeof(g_cli_private_key_pem)) == 0) {
            if (key_management_derive_public_key_hash(g_cli_public_key_pem, g_cli_public_key_hash, sizeof(g_cli_public_key_hash)) == 0) {
                logger_log(LOG_LEVEL_INFO, "Initial ECDSA key pair generated successfully.");
                logger_log(LOG_LEVEL_DEBUG, "Generated Public Key Hash: %s", g_cli_public_key_hash);
            } else {
                logger_log(LOG_LEVEL_ERROR, "Failed to derive public key hash for initial key pair.");
            }
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to auto-generate initial ECDSA key pair. Signing will fail.");
        }
    }

    char command[256];
    int running = 1;

    printf(ANSI_COLOR_CYAN ANSI_STYLE_BOLD "\n==============================================\n");
    printf("  Welcome to the Medical Blockchain CLI!\n");
    printf("==============================================\n" ANSI_COLOR_RESET);
    printf("Type " ANSI_COLOR_YELLOW "'help'" ANSI_COLOR_RESET " for a list of commands, or " ANSI_COLOR_YELLOW "'exit'" ANSI_COLOR_RESET " to quit.\n");
    if (strlen(g_cli_public_key_hash) > 0) {
        printf(ANSI_COLOR_GREEN "Active Wallet Public Key Hash: %s\n" ANSI_COLOR_RESET, g_cli_public_key_hash);
    } else {
        printf(ANSI_COLOR_YELLOW "No active wallet keys. Use 'generate-keys' or ensure startup generation succeeded.\n" ANSI_COLOR_RESET);
    }

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
                if (g_cli_decryption_key_initialized) {
                    handle_print_chain_interactive(g_current_blockchain, g_cli_decryption_key);
                } else {
                    printf(ANSI_COLOR_RED "Decryption key not initialized.\n" ANSI_COLOR_RESET);
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
            handle_generate_keys_interactive();
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
    network_shutdown();
    mempool_shutdown();
    logger_shutdown();
    return 0;
}

static void print_help_menu() {
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "\n--- Available Commands ---\n" ANSI_COLOR_RESET);
    printf("  " ANSI_COLOR_YELLOW "help" ANSI_COLOR_RESET "                     : Display this help menu.\n");
    printf("  " ANSI_COLOR_GREEN "create-blockchain" ANSI_COLOR_RESET "          : Creates a new blockchain with a genesis block.\n");
    printf("  " ANSI_COLOR_GREEN "load-blockchain" ANSI_COLOR_RESET "            : Loads an existing blockchain from disk.\n");
    printf("  " ANSI_COLOR_GREEN "save-blockchain" ANSI_COLOR_RESET "            : Saves the current blockchain to disk.\n");
    printf("  " ANSI_COLOR_GREEN "add-transaction" ANSI_COLOR_RESET "          : Adds a new record transaction.\n");
    printf("  " ANSI_COLOR_GREEN "mine-block" ANSI_COLOR_RESET "               : Mines a new block with pending transactions.\n");
    printf("  " ANSI_COLOR_GREEN "validate-chain" ANSI_COLOR_RESET "           : Validates the integrity of the blockchain.\n");
    printf("  " ANSI_COLOR_GREEN "print-chain" ANSI_COLOR_RESET " [" ANSI_COLOR_YELLOW "--decrypt" ANSI_COLOR_RESET "] : Prints all blocks. Use --decrypt for medical data.\n");
    printf("  " ANSI_COLOR_GREEN "view-transaction <ID>" ANSI_COLOR_RESET " : Displays details of a specific transaction by its ID.\n");
    printf("  " ANSI_COLOR_GREEN "view-block-hash <HASH>" ANSI_COLOR_RESET "  : Displays details of a specific block by its hash.\n");
    printf("  " ANSI_COLOR_GREEN "view-block-height <HEIGHT>" ANSI_COLOR_RESET ": Displays details of a specific block by its height.\n");
    printf("  " ANSI_COLOR_GREEN "print-mempool" ANSI_COLOR_RESET "          : Prints all transactions in the mempool.\n");
    printf("  " ANSI_COLOR_GREEN "generate-keys" ANSI_COLOR_RESET " [--output-private <path>] [--output-public <path>] [--name <str>]: Generates new ECDSA keys for the CLI.\n");
    printf("  " ANSI_COLOR_GREEN "broadcast-transaction" ANSI_COLOR_RESET ": Broadcasts the first pending transaction.\n");
    printf("  " ANSI_COLOR_CYAN "set-log-level" ANSI_COLOR_RESET "            : Set the logger level.\n");
    printf("  " ANSI_COLOR_BLUE "start-listener <port>" ANSI_COLOR_RESET "  : Starts listening for connections.\n");
    printf("  " ANSI_COLOR_BLUE "connect-peer <ip> <port>" ANSI_COLOR_RESET ": Connects to a remote peer.\n");
    printf("  " ANSI_COLOR_BLUE "send-test-message <msg>" ANSI_COLOR_RESET ": Sends a test message to peers.\n");
    printf("  " ANSI_COLOR_RED "exit | quit" ANSI_COLOR_RESET "            : Exits the CLI application.\n");
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--------------------------\n" ANSI_COLOR_RESET);
}

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
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. " ANSI_COLOR_YELLOW "'create-blockchain'" ANSI_COLOR_RESET " or " ANSI_COLOR_YELLOW "'load-blockchain'" ANSI_COLOR_RESET " first.\n");
        return;
    }

    if (strlen(g_cli_private_key_pem) == 0 || strlen(g_cli_public_key_hash) == 0) {
        logger_log(LOG_LEVEL_ERROR, "No active ECDSA keys. Cannot sign transaction. Please 'generate-keys' first.");
        printf(ANSI_COLOR_RED "No active ECDSA keys. Cannot sign transaction. Please " ANSI_COLOR_YELLOW "'generate-keys'" ANSI_COLOR_RESET " first.\n" ANSI_COLOR_RESET);
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

    uint8_t transaction_aes_key[AES_256_KEY_SIZE];
    if (encryption_generate_random_bytes(transaction_aes_key, AES_256_KEY_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate random AES key for transaction data.");
        printf(ANSI_COLOR_RED "Failed to generate random AES key for transaction.\n" ANSI_COLOR_RESET);
        return;
    }

    if (encryption_generate_random_bytes(iv, AES_GCM_IV_SIZE) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate IV for transaction.");
        printf(ANSI_COLOR_RED "Failed to generate IV.\n" ANSI_COLOR_RESET);
        return;
    }

    encrypted_data_len = encryption_encrypt_aes_gcm(
        (const uint8_t*)medical_data_input,
        (int)medical_data_len,
        transaction_aes_key,
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
        ""
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
        free(encrypted_data_buffer);
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to create base transaction object.");
        printf(ANSI_COLOR_RED "Failed to create base transaction object.\n" ANSI_COLOR_RESET);
        if (encrypted_data_buffer) free(encrypted_data_buffer);
    }
}

static void handle_mine_block_interactive(Blockchain* bc) {
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
            block_print(b, encryption_key);
            printf(ANSI_COLOR_CYAN "-----------------\n" ANSI_COLOR_RESET);
        } else {
            logger_log(LOG_LEVEL_ERROR, "Failed to retrieve block at index %zu for printing.", i);
        }
    }
    printf(ANSI_COLOR_MAGENTA ANSI_STYLE_BOLD "--- End of Blockchain Print ---\n" ANSI_COLOR_RESET);
}

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
    int peer_fd = network_start_listener(port);
    if (peer_fd != -1) {
        printf(ANSI_COLOR_GREEN "Network listener started successfully in the background on port %d!\n" ANSI_COLOR_RESET, port);
        printf("You can now continue using the CLI or connect from another node.\n");
        logger_log(LOG_LEVEL_INFO, "Network listener started on port %d.", port);
    } else {
        printf(ANSI_COLOR_RED "Failed to start network listener.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to start network listener on port %d.", port);
    }
}

static void handle_connect_peer_interactive() {
    char *ip_address = strtok(NULL, " ");
    char *port_str = strtok(NULL, " ");

    if (ip_address == NULL || port_str == NULL) {
        printf(ANSI_COLOR_RED "Usage: connect-peer <ip_address> <port>\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_WARN, "Missing arguments for connect-peer command.");
        return;
    }

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        printf(ANSI_COLOR_RED "Invalid port number. Please use a number between 1 and 65535.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Invalid port number entered for connect-peer: %s", port_str);
        return;
    }

    printf(ANSI_COLOR_CYAN "Attempting to connect to peer %s:%d...\n" ANSI_COLOR_RESET, ip_address, port);
    int peer_fd = network_connect_to_peer(ip_address, port);
    if (peer_fd != -1) {
        printf(ANSI_COLOR_GREEN "Connection initiated to %s:%d (FD: %d).\n" ANSI_COLOR_RESET, ip_address, port, peer_fd);
        logger_log(LOG_LEVEL_INFO, "Connection initiated to peer %s:%d (FD: %d).", ip_address, port, peer_fd);
    } else {
        printf(ANSI_COLOR_RED "Failed to connect to %s:%d.\n" ANSI_COLOR_RESET, ip_address, port);
        logger_log(LOG_LEVEL_ERROR, "Failed to connect to peer %s:%d.", ip_address, port);
    }
}

static void handle_send_test_message_interactive() {
    char *message_content = strtok(NULL, "");

    if (message_content == NULL || strlen(message_content) == 0) {
        printf(ANSI_COLOR_RED "Usage: send-test-message <your_message_here>\n" ANSI_COLOR_RESET);
        return;
    }

    while (*message_content == ' ') {
        message_content++;
    }

    logger_log(LOG_LEVEL_INFO, "Sending test message to all connected peers: \"%s\"", message_content);
    network_broadcast_data(MSG_TYPE_TEST_MESSAGE, (const uint8_t*)message_content, strlen(message_content) + 1);
    printf(ANSI_COLOR_GREEN "Test message broadcast to all connected peers.\n" ANSI_COLOR_RESET);
}

static void handle_generate_keys_interactive() {
    printf(ANSI_COLOR_CYAN "Generating a new ECDSA key pair...\n" ANSI_COLOR_RESET);

    // Temp buffers to hold the PEM strings from key_management_generate_key_pair
    char generated_priv_pem[4096] = {0};
    char generated_pub_pem[4096] = {0};
    // Removed: char public_key_hash_temp[SHA256_HEX_LEN + 1] = {0}; // This variable is unused

    char private_output_path[256] = {0};
    char public_output_path[256] = {0};
    char name_for_keys[256] = {0}; // For display purposes
    bool save_to_files = false;

    // Parse additional arguments for --output-private, --output-public, --name
    char *arg = strtok(NULL, " ");
    while (arg != NULL) {
        if (strcmp(arg, "--output-private") == 0) {
            arg = strtok(NULL, " "); // Get the next token as the path
            if (arg) {
                strncpy(private_output_path, arg, sizeof(private_output_path) - 1);
                private_output_path[sizeof(private_output_path) - 1] = '\0'; // Ensure null-termination
                save_to_files = true;
            } else {
                printf(ANSI_COLOR_RED "Error: --output-private requires a file path.\n" ANSI_COLOR_RESET);
                logger_log(LOG_LEVEL_ERROR, "Missing path for --output-private.");
                return;
            }
        } else if (strcmp(arg, "--output-public") == 0) {
            arg = strtok(NULL, " "); // Get the next token as the path
            if (arg) {
                strncpy(public_output_path, arg, sizeof(public_output_path) - 1);
                public_output_path[sizeof(public_output_path) - 1] = '\0'; // Ensure null-termination
                save_to_files = true;
            } else {
                printf(ANSI_COLOR_RED "Error: --output-public requires a file path.\n" ANSI_COLOR_RESET);
                logger_log(LOG_LEVEL_ERROR, "Missing path for --output-public.");
                return;
            }
        } else if (strcmp(arg, "--name") == 0) {
            arg = strtok(NULL, "\""); // Get the name (assumes it might be quoted)
            if (arg) {
                strncpy(name_for_keys, arg, sizeof(name_for_keys) - 1);
                name_for_keys[sizeof(name_for_keys) - 1] = '\0'; // Ensure null-termination
            } else {
                printf(ANSI_COLOR_YELLOW "Warning: --name provided without a value.\n" ANSI_COLOR_RESET);
                logger_log(LOG_LEVEL_WARN, "Missing name for --name argument.");
            }
        }
        arg = strtok(NULL, " "); // Move to the next argument
    }

    if (key_management_generate_key_pair(generated_priv_pem, generated_pub_pem, sizeof(generated_priv_pem)) == 0) {
        // Successfully generated keys in memory (into generated_priv_pem and generated_pub_pem)

        if (save_to_files) {
            if (disk_storage_ensure_dir("data/keys/private_keys") != 0 ||
                disk_storage_ensure_dir("data/keys/public_keys") != 0) {
                logger_log(LOG_LEVEL_ERROR, "Failed to ensure key directories exist for saving files.");
                printf(ANSI_COLOR_RED "Failed to create key storage directories. Keys will NOT be saved to files.\n" ANSI_COLOR_RESET);
            } else {
                FILE *priv_file = fopen(private_output_path, "w");
                if (priv_file) {
                    fprintf(priv_file, "%s", generated_priv_pem);
                    fclose(priv_file);
                    printf(ANSI_COLOR_GREEN "Private key saved to: %s\n" ANSI_COLOR_RESET, private_output_path);
                    logger_log(LOG_LEVEL_INFO, "Private key saved to %s", private_output_path);
                } else {
                    logger_log(LOG_LEVEL_ERROR, "Failed to open private key file for writing: %s. errno: %d", private_output_path, errno);
                    perror(ANSI_COLOR_RED "Error saving private key file" ANSI_COLOR_RESET);
                    printf(ANSI_COLOR_RED "Failed to save private key to file: %s. Check permissions and path.\n" ANSI_COLOR_RESET, private_output_path);
                }

                FILE *pub_file = fopen(public_output_path, "w");
                if (pub_file) {
                    fprintf(pub_file, "%s", generated_pub_pem);
                    fclose(pub_file);
                    printf(ANSI_COLOR_GREEN "Public key saved to: %s\n" ANSI_COLOR_RESET, public_output_path);
                    logger_log(LOG_LEVEL_INFO, "Public key saved to %s", public_output_path);
                } else {
                    logger_log(LOG_LEVEL_ERROR, "Failed to open public key file for writing: %s. errno: %d", public_output_path, errno);
                    perror(ANSI_COLOR_RED "Error saving public key file" ANSI_COLOR_RESET);
                    printf(ANSI_COLOR_RED "Failed to save public key to file: %s. Check permissions and path.\n" ANSI_COLOR_RESET, public_output_path);
                }
            }
        }

        strncpy(g_cli_private_key_pem, generated_priv_pem, sizeof(g_cli_private_key_pem) - 1);
        g_cli_private_key_pem[sizeof(g_cli_private_key_pem) - 1] = '\0';

        strncpy(g_cli_public_key_pem, generated_pub_pem, sizeof(g_cli_public_key_pem) - 1);
        g_cli_public_key_pem[sizeof(g_cli_public_key_pem) - 1] = '\0';


        if (key_management_derive_public_key_hash(g_cli_public_key_pem, g_cli_public_key_hash, sizeof(g_cli_public_key_hash)) == 0) {
            printf(ANSI_COLOR_GREEN "Keys generated successfully and set as active for this session!\n" ANSI_COLOR_RESET);
            printf(ANSI_COLOR_GREEN "Public Key Hash (for transactions): %s\n" ANSI_COLOR_RESET, g_cli_public_key_hash);
            if (strlen(name_for_keys) > 0) {
                printf(ANSI_COLOR_GREEN "Name for keys: %s\n" ANSI_COLOR_RESET, name_for_keys);
            }
            logger_log(LOG_LEVEL_INFO, "New ECDSA key pair generated and set for CLI session. Hash: %s", g_cli_public_key_hash);
        } else {
            printf(ANSI_COLOR_RED "Failed to derive public key hash after generation. Keys may not be usable for transactions.\n" ANSI_COLOR_RESET);
            logger_log(LOG_LEVEL_ERROR, "Failed to derive public key hash after generation.");
        }
    } else {
        printf(ANSI_COLOR_RED "Failed to generate key pair. Check logs for OpenSSL errors.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to generate ECDSA key pair.");
    }
}


static void handle_broadcast_transaction_interactive(Blockchain* bc) {
    if (!bc) {
        logger_log(LOG_LEVEL_ERROR, "Blockchain not created/loaded. Cannot broadcast transaction.");
        printf(ANSI_COLOR_RED "Blockchain not created or loaded. Cannot broadcast transaction.\n" ANSI_COLOR_RESET);
        return;
    }

    if (mempool_get_size() == 0) {
        printf(ANSI_COLOR_YELLOW "No pending transactions in the mempool to broadcast.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_INFO, "Attempted to broadcast, but mempool is empty.");
        return;
    }

    const Transaction* tx_to_broadcast = mempool_get_transaction_by_index(0);
    if (!tx_to_broadcast) {
        printf(ANSI_COLOR_RED "Failed to retrieve transaction for broadcasting from mempool.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to retrieve transaction for broadcasting.");
        return;
    }

    size_t serialized_tx_len;
    uint8_t* serialized_tx = transaction_serialize(tx_to_broadcast, &serialized_tx_len);
    if (!serialized_tx) {
        printf(ANSI_COLOR_RED "Failed to serialize transaction for broadcasting.\n" ANSI_COLOR_RESET);
        logger_log(LOG_LEVEL_ERROR, "Failed to serialize transaction for broadcasting.");
        return;
    }

    logger_log(LOG_LEVEL_INFO, "Attempting to broadcast transaction ID: %s", tx_to_broadcast->transaction_id);
    printf(ANSI_COLOR_CYAN "Broadcasting transaction %s (size: %zu bytes) to all connected peers...\n" ANSI_COLOR_RESET, tx_to_broadcast->transaction_id, serialized_tx_len);

    network_broadcast_data(MSG_TYPE_TRANSACTION, serialized_tx, serialized_tx_len);

    free(serialized_tx);

    printf(ANSI_COLOR_GREEN "Transaction broadcast initiated for ID: %.10s...\n" ANSI_COLOR_RESET, tx_to_broadcast->transaction_id);
    logger_log(LOG_LEVEL_INFO, "Transaction (ID: %s) broadcast initiated.", tx_to_broadcast->transaction_id);
}
