// src/utils/colors.h
#ifndef COLORS_H
#define COLORS_H

#include <stdio.h> // For FILE and fputs

// ANSI Color Codes (still defined as macros for internal use within colors.c)
#define ANSI_COLOR_RED      "\x1b[31m"
#define ANSI_COLOR_GREEN    "\x1b[32m"
#define ANSI_COLOR_YELLOW   "\x1b[33m"
#define ANSI_COLOR_BLUE     "\x1b[34m"
#define ANSI_COLOR_MAGENTA  "\x1b[35m"
#define ANSI_COLOR_CYAN     "\x1b[36m"
#define ANSI_COLOR_RESET    "\x1b[0m" // Resets all attributes
#define ANSI_COLOR_BRIGHT_BLACK "\x1b[90m" // AKA Bright Black or Grey

// ANSI Style Codes
#define ANSI_STYLE_BOLD     "\x1b[1m"
#define ANSI_STYLE_ITALIC   "\x1b[3m" // Not widely supported
#define ANSI_STYLE_UNDERLINE "\x1b[4m"
#define ANSI_STYLE_REVERSED "\x1b[7m"

// --- Helper Functions for Colored Printing ---

/**
 * @brief Prints a message in red to stdout.
 * @param format The format string (like printf).
 * @param ... Variable arguments for the format string.
 */
void print_red(const char* format, ...);

/**
 * @brief Prints a message in green to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_green(const char* format, ...);

/**
 * @brief Prints a message in yellow to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_yellow(const char* format, ...);

/**
 * @brief Prints a message in blue to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_blue(const char* format, ...);

/**
 * @brief Prints a message in magenta to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_magenta(const char* format, ...);

/**
 * @brief Prints a message in cyan to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_cyan(const char* format, ...);

/**
 * @brief Prints a message in bright black (grey) to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_bright_black(const char* format, ...);

/**
 * @brief Prints a bold message to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_bold(const char* format, ...);

/**
 * @brief Prints a message in cyan and bold to stdout.
 * @param format The format string.
 * @param ... Variable arguments.
 */
void print_bold_cyan(const char* format, ...);

#endif // COLORS_H
