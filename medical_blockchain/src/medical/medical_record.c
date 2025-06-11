// src/medical/medical_record.c
#include "medical_record.h"
#include "../utils/logger.h"
#include <json-c/json.h> // json-c library
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // For snprintf

// Helper to safely get a string from a JSON object
static char* get_json_string_value(json_object* obj, const char* key) {
    json_object* value_obj;
    if (json_object_object_get_ex(obj, key, &value_obj) && json_object_is_type(value_obj, json_type_string)) {
        return strdup(json_object_get_string(value_obj));
    }
    return NULL; // Return NULL if key not found or not a string
}

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
    const char* medication,
    const char* dosage,
    const char* allergy,
    const char* severity
) {
    if (patient_id == NULL || type == NULL || description == NULL || doctor == NULL || date == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Required fields for medical record JSON creation are NULL.");
        return NULL;
    }

    json_object *jobj = json_object_new_object();
    if (!jobj) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new JSON object.");
        return NULL;
    }

    json_object_object_add(jobj, "patient_id", json_object_new_string(patient_id));
    json_object_object_add(jobj, "type", json_object_new_string(type));
    json_object_object_add(jobj, "description", json_object_new_string(description));
    json_object_object_add(jobj, "doctor", json_object_new_string(doctor));
    json_object_object_add(jobj, "date", json_object_new_string(date));

    if (medication) json_object_object_add(jobj, "medication", json_object_new_string(medication));
    if (dosage) json_object_object_add(jobj, "dosage", json_object_new_string(dosage));
    if (allergy) json_object_object_add(jobj, "allergy", json_object_new_string(allergy));
    if (severity) json_object_object_add(jobj, "severity", json_object_new_string(severity));

    const char* json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
    if (!json_str) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert JSON object to string.");
        json_object_put(jobj); // Free the JSON object
        return NULL;
    }

    char* result = strdup(json_str);
    json_object_put(jobj); // Free the JSON object

    return result;
}

/**
 * @brief Parses a JSON string into a MedicalRecord structure.
 * @param json_string The JSON string to parse.
 * @return A pointer to a newly allocated MedicalRecord struct on success, NULL on failure.
 * The caller is responsible for freeing this struct using medical_record_destroy.
 */
MedicalRecord* medical_record_parse_json(const char* json_string) {
    if (json_string == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot parse medical record: JSON string is NULL.");
        return NULL;
    }

    json_object *jobj = json_tokener_parse(json_string);
    if (jobj == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to parse JSON string for medical record.");
        return NULL;
    }

    MedicalRecord* record = (MedicalRecord*)calloc(1, sizeof(MedicalRecord)); // Use calloc to zero-initialize
    if (record == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for MedicalRecord.");
        json_object_put(jobj);
        return NULL;
    }

    record->patient_id = get_json_string_value(jobj, "patient_id");
    record->type = get_json_string_value(jobj, "type");
    record->description = get_json_string_value(jobj, "description");
    record->doctor = get_json_string_value(jobj, "doctor");
    record->date = get_json_string_value(jobj, "date");
    record->medication = get_json_string_value(jobj, "medication");
    record->dosage = get_json_string_value(jobj, "dosage");
    record->allergy = get_json_string_value(jobj, "allergy");
    record->severity = get_json_string_value(jobj, "severity");

    json_object_put(jobj); // Free the JSON object, not the strings (they were strdup'd)

    // Basic validation: must have patient_id and type
    if (record->patient_id == NULL || record->type == NULL) {
        logger_log(LOG_LEVEL_WARN, "Parsed medical record missing required fields (patient_id or type).");
        medical_record_destroy(record);
        return NULL;
    }

    return record;
}

/**
 * @brief Converts a MedicalRecord struct back into a JSON string.
 * @param record A pointer to the MedicalRecord struct.
 * @return A dynamically allocated JSON string on success, NULL on failure.
 * The caller is responsible for freeing this string.
 */
char* medical_record_to_json_string(const MedicalRecord* record) {
    if (record == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Cannot convert NULL MedicalRecord to JSON string.");
        return NULL;
    }

    json_object *jobj = json_object_new_object();
    if (!jobj) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new JSON object for MedicalRecord serialization.");
        return NULL;
    }

    if (record->patient_id) json_object_object_add(jobj, "patient_id", json_object_new_string(record->patient_id));
    if (record->type) json_object_object_add(jobj, "type", json_object_new_string(record->type));
    if (record->description) json_object_object_add(jobj, "description", json_object_new_string(record->description));
    if (record->doctor) json_object_object_add(jobj, "doctor", json_object_new_string(record->doctor));
    if (record->date) json_object_object_add(jobj, "date", json_object_new_string(record->date));
    if (record->medication) json_object_object_add(jobj, "medication", json_object_new_string(record->medication));
    if (record->dosage) json_object_object_add(jobj, "dosage", json_object_new_string(record->dosage));
    if (record->allergy) json_object_object_add(jobj, "allergy", json_object_new_string(record->allergy));
    if (record->severity) json_object_object_add(jobj, "severity", json_object_new_string(record->severity));

    const char* json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
    if (!json_str) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert JSON object to string from MedicalRecord.");
        json_object_put(jobj);
        return NULL;
    }

    char* result = strdup(json_str);
    json_object_put(jobj); // Free the JSON object
    return result;
}


/**
 * @brief Frees the memory allocated for a MedicalRecord struct.
 * @param record A pointer to the MedicalRecord struct to destroy.
 */
void medical_record_destroy(MedicalRecord* record) {
    if (record == NULL) return;

    free(record->patient_id);
    free(record->type);
    free(record->description);
    free(record->doctor);
    free(record->date);
    free(record->medication);
    free(record->dosage);
    free(record->allergy);
    free(record->severity);

    free(record);
    logger_log(LOG_LEVEL_DEBUG, "MedicalRecord destroyed.");
}


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
) {
    if (blockchain == NULL || patient_id == NULL || encryption_key == NULL || found_records_count == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input for medical_record_search_by_patient.");
        *found_records_count = 0;
        return NULL;
    }

    MedicalRecord** records_found = NULL;
    size_t current_count = 0;

    for (size_t i = 0; i < blockchain->length; i++) {
        const Block* block = &blockchain->chain[i];
        for (size_t j = 0; j < block->num_transactions; j++) {
            const Transaction* tx = block->transactions[j];

            // Only decrypt if it's a relevant transaction (e.g., recipient_id or sender_id matches patient_id)
            // Or just decrypt all and check patient_id in the medical data. The latter is simpler for now.
            char* decrypted_medical_data = transaction_decrypt_medical_data(tx, encryption_key);
            if (decrypted_medical_data != NULL) {
                MedicalRecord* record = medical_record_parse_json(decrypted_medical_data);
                if (record != NULL) {
                    if (record->patient_id != NULL && strcmp(record->patient_id, patient_id) == 0) {
                        // Found a matching record, add it to our list
                        MedicalRecord** temp_records = (MedicalRecord**)realloc(records_found, (current_count + 1) * sizeof(MedicalRecord*));
                        if (temp_records == NULL) {
                            logger_log(LOG_LEVEL_ERROR, "Failed to reallocate memory for found medical records.");
                            medical_record_destroy(record); // Free the current record
                            // Free all previously found records before returning NULL
                            for (size_t k = 0; k < current_count; k++) {
                                medical_record_destroy(records_found[k]);
                            }
                            free(records_found);
                            free(decrypted_medical_data);
                            *found_records_count = 0;
                            return NULL;
                        }
                        records_found = temp_records;
                        records_found[current_count++] = record;
                    } else {
                        medical_record_destroy(record); // Not a match, free it
                    }
                } else {
                    logger_log(LOG_LEVEL_WARN, "Failed to parse decrypted medical data for transaction %s. Skipping.", tx->transaction_id);
                }
                free(decrypted_medical_data); // Free the decrypted string
            } else {
                logger_log(LOG_LEVEL_WARN, "Failed to decrypt medical data for transaction %s. Skipping.", tx->transaction_id);
            }
        }
    }

    *found_records_count = current_count;
    if (current_count == 0) {
        logger_log(LOG_LEVEL_INFO, "No medical records found for patient ID: %s.", patient_id);
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Found %zu medical records for patient ID: %s.", current_count, patient_id);
    return records_found;
}
