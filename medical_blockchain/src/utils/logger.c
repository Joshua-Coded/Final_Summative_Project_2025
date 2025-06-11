// src/utils/logger.c
#include "logger.h"
#include <stdarg.h> // For va_list, va_start, va_end
#include <stdlib.h> // For exit
#include <string.h> // For strlen
#include <time.h>   // For time, localtime, strftime
#include <errno.h>  // For errno

// Global file pointer for the log file
static FILE* log_file = NULL;

// Global variable for the current log level, default to INFO
LogLevel current_log_level = LOG_LEVEL_INFO;

// Array of strings for log level names
static const char* log_level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE"
};

/**
 * @brief Initializes the logger to write to a specified file.
 * If log_file_path is NULL, logging will only go to stdout/stderr.
 * @param log_file_path The path to the log file.
 * @return 0 on success, -1 on failure.
 */
int logger_init(const char* log_file_path) {
    if (log_file_path != NULL) {
        log_file = fopen(log_file_path, "a"); // Append mode
        if (log_file == NULL) {
            fprintf(stderr, "ERROR: Failed to open log file '%s': %s\n", log_file_path, strerror(errno));
            return -1;
        }
    }
    // Set default log level from compile-time definition if present
#ifdef LOG_LEVEL_DEFAULT
    current_log_level = LOG_LEVEL_DEFAULT;
#endif
    return 0;
}

/**
 * @brief Shuts down the logger, closing any open log files.
 */
void logger_shutdown() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

/**
 * @brief Sets the minimum log level for messages to be recorded.
 * Messages with a lower severity than the current level will be ignored.
 * @param level The new minimum log level.
 */
void logger_set_level(LogLevel level) {
    current_log_level = level;
}

/**
 * @brief Logs a message with a specified severity level.
 * @param level The severity level of the message.
 * @param format The format string for the message (like printf).
 * @param ... Variable arguments for the format string.
 */
void logger_log(LogLevel level, const char* format, ...) {
    // If the message's level is below the current threshold, don't log it
    if (level < current_log_level) {
        return;
    }

    // Get current time
    time_t rawtime;
    struct tm *info;
    char timestamp[20]; // YYYY-MM-DD HH:MM:SS\0

    time(&rawtime);
    info = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", info);

    // Determine output stream (stderr for ERROR/FATAL, stdout for others)
    FILE* output_stream = (level >= LOG_LEVEL_ERROR) ? stderr : stdout;

    // Print to console
    fprintf(output_stream, "[%s] [%s] ", timestamp, log_level_names[level]);
    va_list args_console;
    va_start(args_console, format);
    vfprintf(output_stream, format, args_console);
    va_end(args_console);
    fprintf(output_stream, "\n");
    fflush(output_stream); // Ensure immediate flush for critical messages

    // Print to file if open
    if (log_file != NULL) {
        fprintf(log_file, "[%s] [%s] ", timestamp, log_level_names[level]);
        va_list args_file;
        va_start(args_file, format);
        vfprintf(log_file, format, args_file);
        va_end(args_file);
        fprintf(log_file, "\n");
        fflush(log_file); // Ensure immediate flush for critical messages
    }

    // If FATAL, terminate the program after logging
    if (level == LOG_LEVEL_FATAL) {
        logger_shutdown(); // Close log file before exiting
        exit(EXIT_FAILURE);
    }
}
