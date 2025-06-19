// src/security/key_management.c

#include "key_management.h"
#include "../utils/logger.h"
#include "../crypto/sha256.h"   // For SHA256_DIGEST_LENGTH
#include "../crypto/hasher.h"   // For hasher_bytes_to_hex_buf, hasher_hex_to_bytes_buf, hasher_sha256
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>     // For ERR_print_errors_fp, ERR_clear_error
#include <string.h>
#include <stdlib.h>
#include <stdio.h>           // For stderr

// Define commonly used lengths
#define PUBLIC_KEY_UNCOMPRESSED_LEN 65 // 0x04 || 32-byte X || 32-byte Y for secp256k1
#define ECDSA_MAX_SIGNATURE_LEN 72   // Max DER signature size for secp256k1

// --- Internal Helper Functions ---

// Helper for OpenSSL error logging
static void log_openssl_errors(const char* prefix) {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        logger_log(LOG_LEVEL_ERROR, "%s OpenSSL Error: %s", prefix, err_buf);
    }
}

/**
 * @brief Converts an EC_KEY (public part) to a raw uncompressed public key byte array.
 * @param key The EC_KEY containing the public key.
 * @param buffer Buffer to store the raw bytes.
 * @param buffer_len Size of the buffer.
 * @return Length of the public key bytes (65 for secp256k1) on success, -1 on failure.
 */
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

// The 'ec_key_from_pub_bytes' function and its associated #pragma GCC push/pop
// have been removed as it was unused.

/**
 * @brief Converts an EC_KEY into a PEM-encoded string.
 * @param key The EC_KEY to convert.
 * @param is_private True if saving the private key, false for public.
 * @return A dynamically allocated string containing the PEM data, or NULL on failure.
 * Caller must free this string with `free()`.
 */
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
    pem_string[mem->length] = '\0'; // Null-terminate

    BIO_free_all(bio);
    return pem_string;
}

/**
 * @brief Loads an EC_KEY from a PEM-encoded string.
 * @param pem_string The PEM-encoded key string.
 * @param is_private True if loading a private key, false for public.
 * @return A new EC_KEY object, or NULL on failure. Caller must free with EC_KEY_free().
 */
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


// --- Public API Functions (matching key_management.h) ---

/**
 * @brief Generates a new ECDSA key pair (private and public).
 * @param private_key_pem_out Buffer to store the PEM-encoded private key.
 * @param public_key_pem_out Buffer to store the PEM-encoded public key.
 * @param buffer_size The size of the output buffers.
 * @return 0 on success, -1 on failure.
 */
int key_management_generate_key_pair(char* private_key_pem_out, char* public_key_pem_out, size_t buffer_size) {
    if (!private_key_pem_out || !public_key_pem_out || buffer_size == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for key_management_generate_key_pair.");
        return -1;
    }

    EC_KEY *key = NULL;
    char *priv_pem = NULL;
    char *pub_pem = NULL;
    int ret = -1;

    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create new EC_KEY.");
        log_openssl_errors("key_management_generate_key_pair");
        goto end;
    }

    if (1 != EC_KEY_generate_key(key)) {
        logger_log(LOG_LEVEL_ERROR, "Failed to generate EC key pair.");
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
        logger_log(LOG_LEVEL_ERROR, "Provided buffers are too small for PEM keys.");
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
    return ret;
}

/**
 * @brief Derives the SHA256 hash of a public key.
 * @param public_key_pem The public key in PEM format.
 * @param public_key_hash_out Buffer to store the hex-encoded SHA256 hash.
 * @param buffer_size The size of the public_key_hash_out buffer (at least SHA256_HEX_LEN + 1).
 * @return 0 on success, -1 on failure.
 */
int key_management_derive_public_key_hash(const char* public_key_pem, char* public_key_hash_out, size_t buffer_size) {
    if (!public_key_pem || !public_key_hash_out || buffer_size < SHA256_HEX_LEN + 1) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for key_management_derive_public_key_hash.");
        return -1;
    }

    EC_KEY* pub_key = NULL;
    uint8_t pub_key_bytes[PUBLIC_KEY_UNCOMPRESSED_LEN]; // Corrected: Using defined macro
    int pub_key_bytes_len = 0;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    int ret = -1;

    pub_key = key_from_pem_string(public_key_pem, false);
    if (!pub_key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to load public key from PEM string.");
        goto end;
    }

    pub_key_bytes_len = ec_key_to_pub_bytes(pub_key, pub_key_bytes, sizeof(pub_key_bytes));
    if (pub_key_bytes_len == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to get raw public key bytes.");
        goto end;
    }

    // Use hasher_sha256 instead of sha256 directly for consistency with hasher.h
    if (hasher_sha256(pub_key_bytes, pub_key_bytes_len, hash) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to hash public key bytes.");
        goto end;
    }

    // Use hasher_bytes_to_hex_buf
    hasher_bytes_to_hex_buf(hash, SHA256_DIGEST_LENGTH, public_key_hash_out, buffer_size);
    // hasher_bytes_to_hex_buf does not return NULL on failure, caller must ensure buffer_size is sufficient.
    // We already checked buffer_size at the start.

    logger_log(LOG_LEVEL_INFO, "Public key hash derived successfully.");
    ret = 0;

end:
    if (pub_key) EC_KEY_free(pub_key);
    return ret;
}

/**
 * @brief Signs a SHA256 hash using ECDSA with OpenSSL.
 * @param hash The SHA256 hash (32 bytes) to sign.
 * @param hash_len The length of the hash (should be SHA256_DIGEST_LENGTH).
 * @param private_key_pem Sender's private key in PEM format.
 * @param signature_hex_output Buffer to store the hex-encoded DER signature.
 * @param signature_hex_output_len Size of the signature_hex_output buffer.
 * @return 0 on success, -1 on failure.
 */
int ecdsa_sign_hash(const uint8_t* hash, size_t hash_len, const char* private_key_pem, char* signature_hex_output, size_t signature_hex_output_len) {
    if (!hash || hash_len != SHA256_DIGEST_LENGTH || !private_key_pem || !signature_hex_output || signature_hex_output_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for ecdsa_sign_hash.");
        return -1;
    }

    EC_KEY* priv_key = NULL;
    uint8_t signature_raw[ECDSA_MAX_SIGNATURE_LEN];
    size_t signature_raw_len = 0;
    int ret = -1;

    priv_key = key_from_pem_string(private_key_pem, true);
    if (!priv_key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to load private key from PEM string for signing.");
        goto end;
    }

    if (!EC_KEY_get0_private_key(priv_key)) {
        logger_log(LOG_LEVEL_ERROR, "EC_KEY provided does not contain a private key for signing.");
        goto end;
    }

    unsigned int real_sig_len = 0;
    if (1 != ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature_raw, &real_sig_len, (EC_KEY*)priv_key)) {
        logger_log(LOG_LEVEL_ERROR, "ECDSA_sign failed.");
        log_openssl_errors("ecdsa_sign_hash");
        goto end;
    }
    signature_raw_len = (size_t)real_sig_len;

    // Use hasher_bytes_to_hex_buf
    hasher_bytes_to_hex_buf(signature_raw, signature_raw_len, signature_hex_output, signature_hex_output_len);
    // hasher_bytes_to_hex_buf does not return NULL on failure, caller must ensure buffer_size is sufficient.
    // Check if the output buffer was too small (though our ECDSA_MAX_SIGNATURE_LEN should be safe)
    if (strlen(signature_hex_output) != signature_raw_len * 2) {
        logger_log(LOG_LEVEL_ERROR, "Failed to fully convert signature to hex string (buffer too small?).");
        goto end;
    }

    logger_log(LOG_LEVEL_INFO, "Hash signed successfully.");
    ret = 0;

end:
    if (priv_key) EC_KEY_free(priv_key);
    return ret;
}

/**
 * @brief Verifies an ECDSA signature using OpenSSL.
 * @param hash The original SHA256 hash (32 bytes) that was signed.
 * @param hash_len The length of the hash (should be SHA256_DIGEST_LENGTH).
 * @param signature_hex The hex-encoded DER signature to verify.
 * @param public_key_pem Sender's public key in PEM format.
 * @return true if the signature is valid, false otherwise.
 */
bool ecdsa_verify_signature(const uint8_t* hash, size_t hash_len, const char* signature_hex, const char* public_key_pem) {
    if (!hash || hash_len != SHA256_DIGEST_LENGTH || !signature_hex || !public_key_pem) {
        logger_log(LOG_LEVEL_ERROR, "Invalid input parameters for ecdsa_verify_signature.");
        return false;
    }

    EC_KEY* pub_key = NULL;
    uint8_t signature_raw[ECDSA_MAX_SIGNATURE_LEN];
    size_t signature_raw_len = 0;
    bool is_valid = false;

    // Use hasher_hex_to_bytes_buf. It returns 0 on success, -1 on failure.
    if (hasher_hex_to_bytes_buf(signature_hex, signature_raw, sizeof(signature_raw)) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to convert hex signature to raw bytes.");
        goto end;
    }
    // Calculate the actual raw length from hex_len / 2
    signature_raw_len = strlen(signature_hex) / 2;
    if (signature_raw_len == 0 || signature_raw_len > ECDSA_MAX_SIGNATURE_LEN) { // Sanity check
        logger_log(LOG_LEVEL_ERROR, "Invalid raw signature length after hex conversion.");
        goto end;
    }

    pub_key = key_from_pem_string(public_key_pem, false);
    if (!pub_key) {
        logger_log(LOG_LEVEL_ERROR, "Failed to load public key from PEM string for verification.");
        goto end;
    }

    int ret = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature_raw, (int)signature_raw_len, pub_key);

    if (ret == 1) {
        logger_log(LOG_LEVEL_DEBUG, "ECDSA signature is VALID.");
        is_valid = true;
    } else if (ret == 0) {
        logger_log(LOG_LEVEL_WARN, "ECDSA signature verification FAILED (invalid signature or hash mismatch).");
        log_openssl_errors("ecdsa_verify_signature - verification failed"); // Log specific OpenSSL errors for why it failed
    } else {
        logger_log(LOG_LEVEL_ERROR, "ECDSA_verify returned an error other than 0 or 1.");
        log_openssl_errors("ecdsa_verify_signature - internal error");
    }

end:
    if (pub_key) EC_KEY_free(pub_key);
    return is_valid;
}
