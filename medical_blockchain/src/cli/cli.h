// src/cli/cli.h
#ifndef CLI_H
#define CLI_H

/**
 * @brief Runs the Command Line Interface in interactive mode.
 *
 * This function initializes the logger, sets up the blockchain environment,
 * and enters a loop to process user commands from the console.
 * It does not take command-line arguments directly for processing commands,
 * but rather presents a menu-driven interface.
 *
 * @return 0 on successful execution, 1 on error during initialization.
 */
int cli_run(); // No longer takes argc, argv

#endif
