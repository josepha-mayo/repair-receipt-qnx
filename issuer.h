#ifndef REPAIR_RECEIPT_ISSUER_H
#define REPAIR_RECEIPT_ISSUER_H

#include "receipt.h"
#include <openssl/types.h>

enum { SECRET_BYTES = 32, KEY_HEX_CAPACITY = 2 * SECRET_BYTES + 1,
       SIGNATURE_CAPACITY = 129, ENVELOPE_CAPACITY = 448 };

int secret_from_hex(const char input[KEY_HEX_CAPACITY], unsigned char secret[SECRET_BYTES]);
EVP_PKEY *issuer_from_hex(const char seed[KEY_HEX_CAPACITY]);
int issuer_public_key(const EVP_PKEY *key, char output[KEY_HEX_CAPACITY]);
int issuer_envelope(EVP_PKEY *key, const char *receipt, int version,
                    char output[ENVELOPE_CAPACITY]);

#endif
