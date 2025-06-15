// src/utils/colors.c
#include "colors.h"
#include <stdarg.h> // For va_list, va_start, va_end

// Generic helper function (internal, not exposed in .h) to apply color/style
static void vprint_colored_message(const char* color_code, const char* style_code, const char* format, va_list args) {
    if (color_code) {
        fputs(color_code, stdout);
    }
    if (style_code) {
        fputs(style_code, stdout);
    }
    vprintf(format, args);
    fputs(ANSI_COLOR_RESET, stdout); // Always reset at the end
}

// Specific color printing functions
void print_red(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_RED, NULL, format, args);
    va_end(args);
}

void print_green(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_GREEN, NULL, format, args);
    va_end(args);
}

void print_yellow(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_YELLOW, NULL, format, args);
    va_end(args);
}

void print_blue(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_BLUE, NULL, format, args);
    va_end(args);
}

void print_magenta(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_MAGENTA, NULL, format, args);
    va_end(args);
}

void print_cyan(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_CYAN, NULL, format, args);
    va_end(args);
}

void print_bright_black(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(ANSI_COLOR_BRIGHT_BLACK, NULL, format, args);
    va_end(args);
}

void print_bold(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprint_colored_message(NULL, ANSI_STYLE_BOLD, format, args); // No color, just bold
    va_end(args);
}

// Function for combined color and style
void print_bold_cyan(const char* format, ...) {
    va_list args;
    va_start(args, format);
    // Combine color and style for the generic helper
    fputs(ANSI_COLOR_CYAN, stdout);
    fputs(ANSI_STYLE_BOLD, stdout);
    vprintf(format, args);
    fputs(ANSI_COLOR_RESET, stdout);
    va_end(args);
}
