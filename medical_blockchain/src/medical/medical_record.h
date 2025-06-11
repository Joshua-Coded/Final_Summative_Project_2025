// src/medical/medical_record.h
#ifndef MEDICAL_RECORD_H
#define MEDICAL_RECORD_H

#include <stddef.h> // For size_t
#include "../core/blockchain.h" // For Blockchain struct
#include "../security/encryption.h" // For encryption key

// --- Medical Record Structure (Parsed from JSON) ---
// This struct defines the fields we expect in a medical record JSON object.
// Not all fields will always be present, and will be NULL or 0 if not.
typedef struct MedicalRecord {
    char* patient_id;
    char* type; // e.g., "diagnosis", "prescription", "allergy_update"
    char* description;
    char* doctor;
    char* date; // e.g., "YYYY-MM-DD"

    // Specific fields for different types of records
    char* medication;
    char* dosage;
    char* allergy;
    char* severity;

    // Add more fields as your schema evolves
} MedicalRecord;

/**
 * @brief Creates a JSON string representing a medical record.
 * This is used to prepare data before encryption and creating a transaction.
 *
 * @param patient_id The ID of the patient.
 * @param type The type of medical record (e.g., "diagnosis", "prescription").
 * @param description A general description of the record.
 * @param doctor The doctor associated with the record.
 * @param date The date of the record.
 * @param medication (Optional) For prescription types.
 * @param dosage (Optional) For prescription types.
 * @param allergy (Optional) For allergy updates.
 * @param severity (Optional) For allergy updates.
 * @return A dynamically allocated JSON string on success, NULL on failure.
 * The caller is responsible for freeing this string.
 */
char* medical_record_create_json(
    const char* patient_id,
    const char* type,
    const char* description,
    const char* doctor,
    const char* date,
    const char* medication, // Optional
    const char* dosage,     // Optional
    const char* allergy,    // Optional
    const char* severity    // Optional
);

/**
 * @brief Parses a JSON string into a MedicalRecord structure.
 * @param json_string The JSON string to parse.
 * @return A pointer to a newly allocated MedicalRecord struct on success, NULL on failure.
 * The caller is responsible for freeing this struct using medical_record_destroy.
 */
MedicalRecord* medical_record_parse_json(const char* json_string);

/**
 * @brief Converts a MedicalRecord struct back into a JSON string.
 * @param record A pointer to the MedicalRecord struct.
 * @return A dynamically allocated JSON string on success, NULL on failure.
 * The caller is responsible for freeing this string.
 */
char* medical_record_to_json_string(const MedicalRecord* record);

/**
 * @brief Frees the memory allocated for a MedicalRecord struct.
 * @param record A pointer to the MedicalRecord struct to destroy.
 */
void medical_record_destroy(MedicalRecord* record);

/**
 * @brief Searches the blockchain for medical records related to a specific patient ID.
 *
 * @param blockchain A pointer to the blockchain to search.
 * @param patient_id The patient ID to search for.
 * @param encryption_key The encryption key to decrypt medical data.
 * @param found_records_count A pointer to a size_t to store the number of records found.
 * @return A dynamically allocated array of MedicalRecord pointers on success, NULL if no records found or on error.
 * The caller is responsible for freeing each MedicalRecord in the array and the array itself.
 */
MedicalRecord** medical_record_search_by_patient(
    const Blockchain* blockchain,
    const char* patient_id,
    const uint8_t encryption_key[AES_256_KEY_SIZE],
    size_t* found_records_count
);

#endif // MEDICAL_RECORD_H
