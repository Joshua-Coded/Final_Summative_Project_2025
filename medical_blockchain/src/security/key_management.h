// src/security/key_management.h
#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include "../crypto/sha256.h"

// Max raw binary DER signature length for secp256k1
#define ECDSA_MAX_SIGNATURE_RAW_LEN 72
// Max hex string length for ECDSA signature (72 * 2 = 144)
#define ECDSA_SIGNATURE_HEX_LEN (ECDSA_MAX_SIGNATURE_RAW_LEN * 2)

// Generates a new ECDSA key pair (private and public).
int key_management_generate_key_pair(char* private_key_pem_out, char* public_key_pem_out, size_t buffer_size);

// Derives the SHA256 hash of a public key.
int key_management_derive_public_key_hash(const char* public_key_pem, char* public_key_hash_out, size_t buffer_size);

// Signs a SHA256 hash using ECDSA with OpenSSL.
int ecdsa_sign_hash(const uint8_t* hash, size_t hash_len, const char* private_key_pem, char* signature_hex_output, size_t signature_hex_output_len);

// Verifies an ECDSA signature using OpenSSL.
bool ecdsa_verify_signature(const uint8_t* hash, size_t hash_len, const char* signature_hex, const char* public_key_pem);

#endif // KEY_MANAGEMENT_H
