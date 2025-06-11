// src/utils/logger.h
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h> // For FILE, printf

// Define log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_NONE // To disable all logging
} LogLevel;

// External declaration for the current log level (defined in logger.c)
extern LogLevel current_log_level;

/**
 * @brief Initializes the logger to write to a specified file.
 * If log_file_path is NULL, logging will only go to stdout/stderr.
 * @param log_file_path The path to the log file.
 * @return 0 on success, -1 on failure.
 */
int logger_init(const char* log_file_path);

/**
 * @brief Shuts down the logger, closing any open log files.
 */
void logger_shutdown();

/**
 * @brief Sets the minimum log level for messages to be recorded.
 * Messages with a lower severity than the current level will be ignored.
 * @param level The new minimum log level.
 */
void logger_set_level(LogLevel level);

/**
 * @brief Logs a message with a specified severity level.
 * @param level The severity level of the message.
 * @param format The format string for the message (like printf).
 * @param ... Variable arguments for the format string.
 */
void logger_log(LogLevel level, const char* format, ...);

#endif // LOGGER_H
