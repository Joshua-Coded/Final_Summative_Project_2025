// src/security/key_management.h
#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h> // For EVP_PKEY
#include "../crypto/sha256.h" // Assuming SHA256_DIGEST_LENGTH is here

// --- Key Generation and Management ---

/**
 * @brief Generates a new ECDSA key pair (private and public).
 * @param private_key_pem_out Buffer to store the PEM-encoded private key.
 * @param public_key_pem_out Buffer to store the PEM-encoded public key.
 * @param buffer_size The size of the output buffers.
 * @return 0 on success, -1 on failure.
 */
int key_management_generate_key_pair(char* private_key_pem_out, char* public_key_pem_out, size_t buffer_size);

/**
 * @brief Derives the SHA256 hash of a public key.
 * @param public_key_pem The public key in PEM format.
 * @param public_key_hash_out Buffer to store the hex-encoded SHA256 hash.
 * @param buffer_size The size of the public_key_hash_out buffer (at least SHA256_HEX_LEN + 1).
 * @return 0 on success, -1 on failure.
 */
int key_management_derive_public_key_hash(const char* public_key_pem, char* public_key_hash_out, size_t buffer_size);


// --- Signing and Verification ---

/**
 * @brief Signs a SHA256 hash using ECDSA with OpenSSL.
 * @param hash The SHA256 hash (32 bytes) to sign.
 * @param hash_len The length of the hash (should be SHA256_DIGEST_LENGTH).
 * @param private_key_pem Sender's private key in PEM format.
 * @param signature_hex_output Buffer to store the hex-encoded DER signature.
 * @param signature_hex_output_len Size of the signature_hex_output buffer.
 * @return 0 on success, -1 on failure.
 */
int ecdsa_sign_hash(const uint8_t* hash, size_t hash_len, const char* private_key_pem, char* signature_hex_output, size_t signature_hex_output_len);

/**
 * @brief Verifies an ECDSA signature using OpenSSL.
 * @param hash The original SHA256 hash (32 bytes) that was signed.
 * @param hash_len The length of the hash (should be SHA256_DIGEST_LENGTH).
 * @param signature_hex The hex-encoded DER signature to verify.
 * @param public_key_pem Sender's public key in PEM format.
 * @return true if the signature is valid, false otherwise.
 */
bool ecdsa_verify_signature(const uint8_t* hash, size_t hash_len, const char* signature_hex, const char* public_key_pem);

#endif // KEY_MANAGEMENT_H
