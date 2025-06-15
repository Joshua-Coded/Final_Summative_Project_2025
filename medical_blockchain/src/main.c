// src/main.c
#include "cli/cli.h" // Include your CLI header
// No other includes needed if main just launches the CLI
// All blockchain logic and logging initialization will be handled by cli_run()

int main() { // No longer takes argc, argv if we're just launching the CLI
    return cli_run(); // Call the interactive CLI function
}
