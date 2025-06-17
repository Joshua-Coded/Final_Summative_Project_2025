// src/medical/medical_record.c
#include "medical_record.h"
#include "../utils/logger.h"
#include "../utils/colors.h"
#include "../crypto/hasher.h"
#include <cjson/cJSON.h> // Make sure this is correctly linked in your Makefile
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // For time() and time_t

// Forward declaration for internal JSON helper
static void copy_json_string_value(const cJSON* obj, const char* key, char* dest, size_t dest_size);

/**
 * @brief Creates a new medical record structure.
 * Initializes the record with default values.
 * @return A pointer to the newly allocated MedicalRecord, or NULL on failure.
 */
MedicalRecord* medical_record_create() {
    MedicalRecord* record = (MedicalRecord*)calloc(1, sizeof(MedicalRecord));
    if (record == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for MedicalRecord.");
        return NULL;
    }
    record->timestamp = time(NULL); // Set creation timestamp
    // Initialize data pointer to NULL and length to 0
    record->data = NULL;
    record->data_len = 0;
    record->record_hash[0] = '\0'; // Initialize hash string
    return record;
}

/**
 * @brief Sets the raw data (e.g., JSON string) for a medical record.
 * This function will also calculate the record_hash.
 * @param record The MedicalRecord to update.
 * @param raw_data The raw data (e.g., JSON string) to store.
 * @param raw_data_len The length of the raw data.
 * @return 0 on success, -1 on failure.
 */
int medical_record_set_data(MedicalRecord* record, const uint8_t* raw_data, size_t raw_data_len) {
    if (record == NULL || raw_data == NULL || raw_data_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for medical_record_set_data.");
        return -1;
    }

    // Free existing data if any
    if (record->data != NULL) {
        free(record->data);
        record->data = NULL;
        record->data_len = 0;
    }

    record->data = (uint8_t*)malloc(raw_data_len);
    if (record->data == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for medical record data.");
        return -1;
    }
    memcpy(record->data, raw_data, raw_data_len);
    record->data_len = raw_data_len;

    // Calculate and set the hash of the raw data
    uint8_t hash_binary[SHA256_DIGEST_LENGTH];
    if (medical_record_calculate_hash(record, hash_binary) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to calculate hash for medical record data.");
        return -1;
    }

    char* hex_hash = hasher_bytes_to_hex(hash_binary, SHA256_DIGEST_LENGTH);
    if (hex_hash) {
        strncpy(record->record_hash, hex_hash, MEDICAL_RECORD_HASH_LEN);
        record->record_hash[MEDICAL_RECORD_HASH_LEN] = '\0';
        free(hex_hash);
    } else {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert record hash to hex.");
        return -1;
    }

    return 0;
}


/**
 * @brief Calculates the SHA256 hash of the medical record's data.
 * This hash is used for the record_hash field in the struct.
 * @param record The medical record whose data will be hashed.
 * @param output_hash A buffer of SHA256_DIGEST_LENGTH to store the binary hash.
 * @return 0 on success, -1 on failure.
 */
int medical_record_calculate_hash(const MedicalRecord* record, uint8_t output_hash[SHA256_DIGEST_LENGTH]) {
    if (record == NULL || record->data == NULL || record->data_len == 0 || output_hash == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for medical_record_calculate_hash.");
        return -1;
    }
    // Hash the raw data (which is expected to be a JSON string or similar)
    hasher_sha256(record->data, record->data_len, output_hash);
    return 0;
}

/**
 * @brief Converts a MedicalRecord struct to a cJSON object.
 * This function serializes the MedicalRecord's core fields (hash, data_len, timestamp)
 * and includes the raw 'data' as a string within the JSON.
 * @param record The MedicalRecord to convert.
 * @return A pointer to the cJSON object, or NULL on failure. Caller must free with cJSON_Delete.
 */
cJSON* medical_record_to_json(const MedicalRecord* record) {
    if (record == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot convert NULL MedicalRecord to JSON.");
        return NULL;
    }

    cJSON* jobj = cJSON_CreateObject();
    if (jobj == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create JSON object for MedicalRecord.");
        return NULL;
    }

    cJSON_AddStringToObject(jobj, "record_hash", record->record_hash);
    cJSON_AddNumberToObject(jobj, "data_len", (double)record->data_len);
    cJSON_AddNumberToObject(jobj, "timestamp", (double)record->timestamp);

    // Add the raw data as a JSON string.
    if (record->data != NULL && record->data_len > 0) {
        char* data_str = (char*)malloc(record->data_len + 1);
        if (data_str == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for data_str in medical_record_to_json.");
            cJSON_Delete(jobj);
            return NULL;
        }
        memcpy(data_str, record->data, record->data_len);
        data_str[record->data_len] = '\0'; // Null-terminate

        cJSON_AddStringToObject(jobj, "data", data_str);
        free(data_str); // cJSON_AddStringToObject makes a copy, so free our temp buffer
    } else {
        cJSON_AddStringToObject(jobj, "data", ""); // Add empty string if no data
    }


    logger_log(LOG_LEVEL_DEBUG, "MedicalRecord converted to JSON.");
    return jobj;
}

/**
 * @brief Converts a cJSON object into a MedicalRecord struct.
 * This function parses the cJSON object and reconstructs a MedicalRecord,
 * including its raw 'data' field.
 * @param jobj The cJSON object to convert.
 * @return A pointer to the newly created MedicalRecord, or NULL on failure. Caller must free with medical_record_destroy.
 */
MedicalRecord* medical_record_from_json(const cJSON* jobj) {
    if (jobj == NULL || !cJSON_IsObject(jobj)) {
        logger_log(LOG_LEVEL_ERROR, "Invalid JSON object for MedicalRecord deserialization.");
        return NULL;
    }

    MedicalRecord* record = medical_record_create();
    if (record == NULL) {
        return NULL; // Error already logged by medical_record_create
    }

    // Extract record_hash
    copy_json_string_value(jobj, "record_hash", record->record_hash, sizeof(record->record_hash));

    // Extract data_len
    cJSON* data_len_obj = cJSON_GetObjectItemCaseSensitive(jobj, "data_len");
    if (cJSON_IsNumber(data_len_obj)) {
        record->data_len = (size_t)cJSON_GetNumberValue(data_len_obj);
    } else {
        logger_log(LOG_LEVEL_WARN, "JSON 'data_len' not found or not a number, defaulting to 0.");
        record->data_len = 0;
    }

    // Extract timestamp
    cJSON* timestamp_obj = cJSON_GetObjectItemCaseSensitive(jobj, "timestamp");
    if (cJSON_IsNumber(timestamp_obj)) {
        record->timestamp = (time_t)cJSON_GetNumberValue(timestamp_obj);
    } else {
        logger_log(LOG_LEVEL_WARN, "JSON 'timestamp' not found or not a number, defaulting to current time.");
        record->timestamp = time(NULL); // Default to current time if not in JSON
    }

    // Extract raw data string
    cJSON* data_obj = cJSON_GetObjectItemCaseSensitive(jobj, "data");
    if (cJSON_IsString(data_obj) && data_obj->valuestring != NULL) {
        if (record->data) free(record->data); // Should not happen for a newly created record

        size_t string_len = strlen(data_obj->valuestring);
        record->data = (uint8_t*)malloc(string_len + 1); // +1 for null terminator if treating as string
        if (record->data == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for record data during deserialization.");
            medical_record_destroy(record); // Clean up partially created record
            return NULL;
        }
        memcpy(record->data, data_obj->valuestring, string_len);
        record->data[string_len] = '\0'; // Ensure null termination
        record->data_len = string_len;   // Update data_len to actual string length
    } else {
        logger_log(LOG_LEVEL_WARN, "JSON 'data' field not found or not a string. Medical record data will be empty.");
        record->data = NULL;
        record->data_len = 0;
    }

    // Verify hash (optional, but good for integrity)
    uint8_t recomputed_hash_binary[SHA256_DIGEST_LENGTH];
    if (record->data != NULL && record->data_len > 0 &&
        medical_record_calculate_hash(record, recomputed_hash_binary) == 0) {
        char* recomputed_hex_hash = hasher_bytes_to_hex(recomputed_hash_binary, SHA256_DIGEST_LENGTH);
        if (recomputed_hex_hash && strcmp(record->record_hash, recomputed_hex_hash) != 0) {
            logger_log(LOG_LEVEL_WARN, "Deserialized MedicalRecord hash mismatch! Original: %s, Recomputed: %s",
                                 record->record_hash, recomputed_hex_hash);
        }
        if (recomputed_hex_hash) free(recomputed_hex_hash);
    } else {
          logger_log(LOG_LEVEL_WARN, "Could not recompute hash for deserialized medical record (data might be empty).");
    }

    logger_log(LOG_LEVEL_DEBUG, "MedicalRecord deserialized from JSON.");
    return record;
}


/**
 * @brief Frees all memory associated with a MedicalRecord.
 * @param record A pointer to the MedicalRecord to destroy.
 */
void medical_record_destroy(MedicalRecord* record) {
    if (record == NULL) {
        return;
    }
    if (record->data != NULL) {
        free(record->data);
        record->data = NULL;
    }
    free(record);
    logger_log(LOG_LEVEL_DEBUG, "MedicalRecord destroyed.");
}


/**
 * @brief Prints the details of a medical record (including its internal JSON data if available).
 * @param record The medical record to print.
 */
void medical_record_print(const MedicalRecord* record) {
    if (record == NULL) {
        printf(ANSI_COLOR_RED "NULL Medical Record\n" ANSI_COLOR_RESET);
        return;
    }

    printf(ANSI_COLOR_CYAN "--- Medical Record Details ---\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_CYAN "  Record Hash:           " ANSI_COLOR_RESET "%s\n", record->record_hash);
    printf(ANSI_COLOR_CYAN "  Data Length:           " ANSI_COLOR_RESET "%zu bytes\n", record->data_len);
    printf(ANSI_COLOR_CYAN "  Timestamp:             " ANSI_COLOR_RESET "%ld (" ANSI_COLOR_BRIGHT_BLACK "%s" ANSI_COLOR_RESET ")", (long)record->timestamp, ctime((const time_t*)&record->timestamp)); // ctime adds newline

    printf(ANSI_COLOR_YELLOW "  Raw Data Content:\n" ANSI_COLOR_RESET);
    if (record->data != NULL && record->data_len > 0) {
        // Assuming data is a JSON string, print it.
        printf(ANSI_COLOR_YELLOW "    %.*s\n" ANSI_COLOR_RESET, (int)record->data_len, (char*)record->data);

        // Optional: If you want to parse and pretty-print the internal JSON data here
        cJSON* inner_json = cJSON_Parse((const char*)record->data);
        if (inner_json) {
            char* printed_json = cJSON_PrintUnformatted(inner_json); // Or cJSON_Print for pretty-print
            if (printed_json) {
                printf(ANSI_COLOR_YELLOW "    (Parsed Content): %s\n" ANSI_COLOR_RESET, printed_json);
                free(printed_json);
            }
            cJSON_Delete(inner_json);
        } else {
            logger_log(LOG_LEVEL_WARN, "Could not parse internal data as JSON. Printing as raw string.");
        }

    } else {
        printf(ANSI_COLOR_YELLOW "    (No data available)\n" ANSI_COLOR_RESET);
    }
    printf(ANSI_COLOR_CYAN "--------------------------------------------------\n" ANSI_COLOR_RESET);
}

// --- Internal Helper Functions ---

/**
 * @brief Copies a string value from a JSON object item to a destination buffer.
 * @param obj The cJSON object.
 * @param key The key of the string item.
 * @param dest The destination buffer.
 * @param dest_size The size of the destination buffer.
 */
static void copy_json_string_value(const cJSON* obj, const char* key, char* dest, size_t dest_size) {
    if (obj == NULL || key == NULL || dest == NULL || dest_size == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for copy_json_string_value.");
        if (dest && dest_size > 0) dest[0] = '\0';
        return;
    }
    cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(item) && item->valuestring != NULL) {
        strncpy(dest, item->valuestring, dest_size - 1);
        dest[dest_size - 1] = '\0';
    } else {
        logger_log(LOG_LEVEL_WARN, "JSON item '%s' not found or not a string. Setting destination to empty string.", key);
        dest[0] = '\0';
    }
}
