// src/security/key_management.c

#include "key_management.h"
#include "../utils/logger.h"
#include "../crypto/sha256.h"
#include "../crypto/hasher.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h> // Required for FILE operations (fopen, fprintf, fclose)
#include <errno.h> // Required for strerror(errno)

#define PUBLIC_KEY_UNCOMPRESSED_LEN 65
#define ECDSA_MAX_SIGNATURE_LEN 72 // This defines the maximum length of the DER-encoded signature.
                                   // Note: OpenSSL's ECDSA_sign will return the actual length in `real_sig_len`.
                                   // The hexadecimal representation will be twice this length.

// Assuming these are defined in key_management.h or elsewhere:
// #define ECDSA_SIGNATURE_HEX_LEN (ECDSA_MAX_SIGNATURE_LEN * 2)
// #define ECDSA_MAX_SIGNATURE_RAW_LEN ECDSA_MAX_SIGNATURE_LEN

// Helper for OpenSSL error logging.
static void log_openssl_errors(const char* prefix) {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        logger_log(LOG_LEVEL_ERROR, "%s OpenSSL Error: %s", prefix, err_buf);
    }
}

// Converts an EC_KEY (public part) to a raw uncompressed public key byte array.
static int ec_key_to_pub_bytes(const EC_KEY* key, uint8_t* buffer, size_t buffer_len) {
    if (!key || !buffer) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input to ec_key_to_pub_bytes.");
        return -1;
    }
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    if (!group || !point) {
        logger_log(LOG_LEVEL_ERROR, "EC_KEY does not contain a valid public key point.");
        return -1;
    }
    size_t required_len = PUBLIC_KEY_UNCOMPRESSED_LEN;
    if (buffer_len < required_len) {
        logger_log(LOG_LEVEL_ERROR, "Buffer too small for public key bytes (required %zu, got %zu).", required_len, buffer_len);
        return -1;
    }
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buffer, required_len, NULL) == 0) {
        logger_log(LOG_LEVEL_ERROR, "EC_POINT_point2oct failed.");
        log_openssl_errors("ec_key_to_pub_bytes");
        return -1;
    }
    return (int)required_len;
}

// Converts an EC_KEY into a PEM-encoded string.
static char* key_to_pem_string(const EC_KEY* key, bool is_private) {
    if (!key) {
        logger_log(LOG_LEVEL_ERROR, "Invalid EC_KEY input to key_to_pem_string.");
        return NULL;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        logger_log(LOG_LEVEL_ERROR, "BIO_new failed.");
        log_openssl_errors("key_to_pem_string");
        return NULL;
    }
    int ret = 0;
    if (is_private) {
        ret = PEM_write_bio_ECPrivateKey(bio, (EC_KEY*)key, NULL, NULL, 0, NULL, NULL);
    } else {
        ret = PEM_write_bio_EC_PUBKEY(bio, (EC_KEY*)key);
    }
    if (ret != 1) {
        logger_log(LOG_LEVEL_ERROR, "PEM_write_bio failed for key to PEM string.");
        log_openssl_errors("key_to_pem_string");
        BIO_free_all(bio);
        return NULL;
    }
    BUF_MEM *mem;
    BIO_get_mem_ptr(bio, &mem);
    char* pem_string = (char*)malloc(mem->length + 1);
    if (!pem_string) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for PEM string.");
        BIO_free_all(bio);
        return NULL;
    }
    memcpy(pem_string, mem->data, mem->length);
    pem_string[mem->length] = '\0';
    BIO_free_all(bio);
    return pem_string;
}

// Loads an EC_KEY from a PEM-encoded string.
static EC_KEY* key_from_pem_string(const char* pem_string, bool is_private) {
    if (!pem_string) {
        logger_log(LOG_LEVEL_ERROR, "Invalid PEM string input to key_from_pem_string.");
        return NULL;
    }
    BIO *bio = BIO_new_mem_buf((const void*)pem_string, -1);
    if (!bio) {
        logger_log(LOG_LEVEL_ERROR, "BIO_new_mem_buf failed.");
        log_openssl_errors("key_from_pem_string");
        return NULL;
    }
    EC_KEY *key = NULL;
    if (is_private) {
        key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    } else {
        key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    }
    if (!key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to read key from PEM string. Check format/type.");
        log_openssl_errors("key_from_pem_string");
    }
    BIO_free_all(bio);
    return key;
}

// Generates a new ECDSA key pair (private and public).
int key_management_generate_key_pair(char* private_key_pem_out, char* public_key_pem_out, size_t buffer_size) {
    if (!private_key_pem_out || !public_key_pem_out || buffer_size == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for key_management_generate_key_pair.");
        return -1;
    }
    EC_KEY *key = NULL;
    char *priv_pem = NULL;
    char *pub_pem = NULL;
    int ret = -1;

    // Load OpenSSL error strings (important for debugging)
    ERR_load_crypto_strings();

    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new EC_KEY (curve name).");
        log_openssl_errors("key_management_generate_key_pair");
        goto end;
    }
    if (1 != EC_KEY_generate_key(key)) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate EC key pair.");
        log_openssl_errors("key_management_generate_key_pair");
        goto end;
    }
    
    // Ensure the key has its public key set (should be automatic after generate_key, but good to be explicit)
    // EC_KEY_set_public_key is rarely needed after EC_KEY_generate_key as it's typically handled internally.
    // However, keeping it does no harm if the public key point is valid.
    if (!EC_KEY_get0_public_key(key)) { // Check if public key exists
        logger_log(LOG_LEVEL_ERROR, "Generated EC_KEY does not have a public key.");
        log_openssl_errors("key_management_generate_key_pair");
        goto end;
    }

    priv_pem = key_to_pem_string(key, true);
    if (!priv_pem) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert private key to PEM string.");
        goto end;
    }
    pub_pem = key_to_pem_string(key, false);
    if (!pub_pem) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert public key to PEM string.");
        goto end;
    }

    if (strlen(priv_pem) + 1 > buffer_size || strlen(pub_pem) + 1 > buffer_size) {
        logger_log(LOG_LEVEL_ERROR, "Provided buffers are too small for PEM keys. Private key length: %zu, Public key length: %zu, Buffer size: %zu", strlen(priv_pem), strlen(pub_pem), buffer_size);
        goto end;
    }
    strcpy(private_key_pem_out, priv_pem);
    strcpy(public_key_pem_out, pub_pem);
    logger_log(LOG_LEVEL_INFO, "Key pair generated and PEM strings copied.");
    ret = 0;

end:
    if (key) EC_KEY_free(key);
    if (priv_pem) free(priv_pem);
    if (pub_pem) free(pub_pem);
    // Cleanup OpenSSL error queue
    ERR_free_strings();
    return ret;
}

// Derives the SHA256 hash of a public key.
int key_management_derive_public_key_hash(const char* public_key_pem, char* public_key_hash_out, size_t buffer_size) {
    if (!public_key_pem || !public_key_hash_out || buffer_size < SHA256_HEX_LEN + 1) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for key_management_derive_public_key_hash.");
        return -1;
    }
    EC_KEY* pub_key = NULL;
    uint8_t pub_key_bytes[PUBLIC_KEY_UNCOMPRESSED_LEN];
    int pub_key_bytes_len = 0;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    int ret = -1;

    ERR_load_crypto_strings(); // Load error strings for debugging

    pub_key = key_from_pem_string(public_key_pem, false);
    if (!pub_key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to load public key from PEM string for hash derivation.");
        goto end;
    }
    pub_key_bytes_len = ec_key_to_pub_bytes(pub_key, pub_key_bytes, sizeof(pub_key_bytes));
    if (pub_key_bytes_len == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to get raw public key bytes for hashing.");
        goto end;
    }
    if (hasher_sha256(pub_key_bytes, pub_key_bytes_len, hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash public key bytes.");
        goto end;
    }
    hasher_bytes_to_hex_buf(hash, SHA256_DIGEST_LENGTH, public_key_hash_out, buffer_size);
    logger_log(LOG_LEVEL_INFO, "Public key hash derived successfully.");
    ret = 0;
end:
    if (pub_key) EC_KEY_free(pub_key);
    ERR_free_strings(); // Cleanup error strings
    return ret;
}

// Signs a SHA256 hash using ECDSA with OpenSSL.
int ecdsa_sign_hash(const uint8_t* hash, size_t hash_len, const char* private_key_pem, char* signature_hex_output, size_t signature_hex_output_len) {
    // Note: ECDSA_SIGNATURE_HEX_LEN and ECDSA_MAX_SIGNATURE_RAW_LEN are expected to be defined in key_management.h or config.h
    // if (!hash || hash_len != SHA256_DIGEST_LENGTH || !private_key_pem || !signature_hex_output || signature_hex_output_len < ECDSA_SIGNATURE_HEX_LEN + 1) {
    // The following check is more robust if ECDSA_MAX_SIGNATURE_LEN is the only pre-defined constant
    if (!hash || hash_len != SHA256_DIGEST_LENGTH || !private_key_pem || !signature_hex_output || signature_hex_output_len < (ECDSA_MAX_SIGNATURE_LEN * 2 + 1)) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for ecdsa_sign_hash. Hash length must be %d, signature_hex_output_len must be at least %d.", SHA256_DIGEST_LENGTH, (int)(ECDSA_MAX_SIGNATURE_LEN * 2 + 1));
        return -1;
    }
    EC_KEY* priv_key = NULL;
    uint8_t signature_raw[ECDSA_MAX_SIGNATURE_LEN]; // Use ECDSA_MAX_SIGNATURE_LEN for raw buffer size
    unsigned int real_sig_len = 0; // Use unsigned int for OpenSSL's ECDSA_sign
    int ret = -1;

    ERR_load_crypto_strings();

    priv_key = key_from_pem_string(private_key_pem, true);
    if (!priv_key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to load private key from PEM string for signing.");
        goto end;
    }
    if (!EC_KEY_get0_private_key(priv_key)) {
        logger_log(LOG_LEVEL_ERROR, "EC_KEY provided does not contain a private key for signing.");
        goto end;
    }

    if (1 != ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature_raw, &real_sig_len, (EC_KEY*)priv_key)) {
        logger_log(LOG_LEVEL_ERROR, "ECDSA_sign failed.");
        log_openssl_errors("ecdsa_sign_hash");
        goto end;
    }

    // Now convert the raw signature bytes to a hex string
    // Removed the 'if' condition here because hasher_bytes_to_hex_buf is likely void
    hasher_bytes_to_hex_buf(signature_raw, (size_t)real_sig_len, signature_hex_output, signature_hex_output_len);
    
    // Check if the output buffer was sufficient for the hex conversion
    // This check is crucial since hasher_bytes_to_hex_buf might not return a status.
    if (strlen(signature_hex_output) != (size_t)real_sig_len * 2) {
        logger_log(LOG_LEVEL_ERROR, "Hex signature conversion resulted in unexpected length (raw len: %u, hex len: %zu). Buffer too small or error.", real_sig_len, strlen(signature_hex_output));
        goto end;
    }

    logger_log(LOG_LEVEL_INFO, "Hash signed successfully. Signature length: %u bytes (raw), %zu bytes (hex)", real_sig_len, strlen(signature_hex_output));
    ret = 0;

end:
    if (priv_key) EC_KEY_free(priv_key);
    ERR_free_strings();
    return ret;
}

// Verifies an ECDSA signature using OpenSSL.
bool ecdsa_verify_signature(const uint8_t* hash, size_t hash_len, const char* signature_hex, const char* public_key_pem) {
    if (!hash || hash_len != SHA256_DIGEST_LENGTH || !signature_hex || !public_key_pem || strlen(signature_hex) == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for ecdsa_verify_signature.");
        return false;
    }
    EC_KEY* pub_key = NULL;
    uint8_t signature_raw[ECDSA_MAX_SIGNATURE_LEN]; // Use ECDSA_MAX_SIGNATURE_LEN for raw buffer size
    size_t signature_raw_len = 0;
    bool is_valid = false;

    ERR_load_crypto_strings();

    // Convert hex signature to raw bytes
    // Assuming hasher_hex_to_bytes_buf also returns void or has its own error handling
    hasher_hex_to_bytes_buf(signature_hex, signature_raw, sizeof(signature_raw));
    
    // Check for potential issues with hex to bytes conversion:
    // If hasher_hex_to_bytes_buf returned an int, we'd check it. Since it doesn't,
    // we assume it performs the conversion or logs internally.
    // The length check below acts as a post-conversion validation.
    
    signature_raw_len = strlen(signature_hex) / 2; // Calculate actual raw length from hex string

    if (signature_raw_len == 0 || signature_raw_len > ECDSA_MAX_SIGNATURE_LEN) { // Use ECDSA_MAX_SIGNATURE_LEN here
        logger_log(LOG_LEVEL_ERROR, "Invalid raw signature length after hex conversion (%zu bytes). Expected between 1 and %d.", signature_raw_len, ECDSA_MAX_SIGNATURE_LEN);
        goto end;
    }

    pub_key = key_from_pem_string(public_key_pem, false);
    if (!pub_key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to load public key from PEM string for verification.");
        goto end;
    }
    
    // Check if the public key has a valid public point
    if (!EC_KEY_get0_public_key(pub_key)) {
        logger_log(LOG_LEVEL_ERROR, "Public key loaded from PEM does not have a valid public point.");
        goto end;
    }

    int ret = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature_raw, (int)signature_raw_len, pub_key);
    if (ret == 1) {
        logger_log(LOG_LEVEL_DEBUG, "ECDSA signature is VALID.");
        is_valid = true;
    } else if (ret == 0) {
        logger_log(LOG_LEVEL_WARN, "ECDSA signature verification FAILED (invalid signature or hash mismatch).");
        log_openssl_errors("ecdsa_verify_signature - verification failed");
    } else {
        logger_log(LOG_LEVEL_ERROR, "ECDSA_verify returned an error other than 0 or 1.");
        log_openssl_errors("ecdsa_verify_signature - internal error");
    }
end:
    if (pub_key) EC_KEY_free(pub_key);
    ERR_free_strings();
    return is_valid;
}


/**
 * @brief Saves a PEM-encoded key string to a specified file.
 *
 * @param key_pem The null-terminated PEM string of the key (private or public).
 * @param filepath The path to the file where the key will be saved.
 * @return 0 on success, -1 on error.
 */
int key_management_save_key_to_file(const char* key_pem, const char* filepath) {
    if (!key_pem || !filepath || strlen(key_pem) == 0 || strlen(filepath) == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for key_management_save_key_to_file: key_pem or filepath is NULL/empty.");
        return -1;
    }

    FILE* fp = fopen(filepath, "w");
    if (fp == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to open file '%s' for writing key: %s", filepath, strerror(errno));
        return -1;
    }

    if (fprintf(fp, "%s", key_pem) < 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to write key to file '%s': %s", filepath, strerror(errno));
        fclose(fp);
        return -1;
    }

    fclose(fp);
    logger_log(LOG_LEVEL_INFO, "Key successfully saved to '%s'.", filepath);
    return 0;
}
