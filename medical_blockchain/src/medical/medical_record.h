// src/medical/medical_record.h
#ifndef MEDICAL_RECORD_H
#define MEDICAL_RECORD_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/sha256.h" // For SHA256_DIGEST_LENGTH, SHA256_HEX_LEN
#include "../security/encryption.h" // For AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE
#include <time.h> // For time_t

// Define maximum lengths for string fields for consistency and buffer sizing
#define MEDICAL_RECORD_HASH_LEN SHA256_HEX_LEN // 64 hex chars + NULL
#define MEDICAL_DATA_MAX_LEN 4096 // Max size for the raw medical data JSON string

// Forward declaration for cJSON (if used internally in .c)
// typedef struct cJSON cJSON;

/**
 * @brief Represents a single medical record.
 * The 'data' field is expected to be a JSON string containing
 * detailed medical information like type, description, medication, etc.
 * This structure stores the *encrypted* or *raw* data for hashing and storage.
 */
typedef struct MedicalRecord {
    char record_hash[MEDICAL_RECORD_HASH_LEN + 1]; // SHA256 hash of the 'data' field (unencrypted)
    uint8_t* data;                               // Raw medical data (e.g., JSON string)
    size_t data_len;                             // Length of the raw medical data
    time_t timestamp;                            // Timestamp of record creation
} MedicalRecord;

/**
 * @brief Creates a new medical record structure.
 * Initializes the record with default values.
 * @return A pointer to the newly allocated MedicalRecord, or NULL on failure.
 */
MedicalRecord* medical_record_create();

/**
 * @brief Sets the raw data (e.g., JSON string) for a medical record.
 * This function will also calculate the record_hash.
 * @param record The MedicalRecord to update.
 * @param raw_data The raw data (e.g., JSON string) to store.
 * @param raw_data_len The length of the raw data.
 * @return 0 on success, -1 on failure.
 */
int medical_record_set_data(MedicalRecord* record, const uint8_t* raw_data, size_t raw_data_len);

/**
 * @brief Calculates the SHA256 hash of the medical record's data.
 * This hash is used for the record_hash field in the struct.
 * @param record The medical record whose data will be hashed.
 * @param output_hash A buffer of SHA256_DIGEST_LENGTH to store the binary hash.
 * @return 0 on success, -1 on failure.
 */
int medical_record_calculate_hash(const MedicalRecord* record, uint8_t output_hash[SHA256_DIGEST_LENGTH]);

/**
 * @brief Converts a MedicalRecord struct to a cJSON object.
 * This function serializes the MedicalRecord's core fields (hash, data_len, timestamp)
 * and includes the raw 'data' as a string within the JSON.
 * @param record The MedicalRecord to convert.
 * @return A pointer to the cJSON object, or NULL on failure. Caller must free with cJSON_Delete.
 */
struct cJSON* medical_record_to_json(const MedicalRecord* record);

/**
 * @brief Converts a cJSON object into a MedicalRecord struct.
 * This function parses the cJSON object and reconstructs a MedicalRecord,
 * including its raw 'data' field.
 * @param jobj The cJSON object to convert.
 * @return A pointer to the newly created MedicalRecord, or NULL on failure. Caller must free with medical_record_destroy.
 */
MedicalRecord* medical_record_from_json(const struct cJSON* jobj);

/**
 * @brief Frees all memory associated with a MedicalRecord.
 * @param record A pointer to the MedicalRecord to destroy.
 */
void medical_record_destroy(MedicalRecord* record);

/**
 * @brief Prints the details of a medical record (including its internal JSON data if available).
 * @param record The medical record to print.
 */
void medical_record_print(const MedicalRecord* record);

#endif // MEDICAL_RECORD_H
