#include "issuer.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

static int nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

int secret_from_hex(const char input[KEY_HEX_CAPACITY], unsigned char secret[SECRET_BYTES])
{
    if (strlen(input) != KEY_HEX_CAPACITY - 1) {
        return 0;
    }
    for (size_t offset = 0; offset < SECRET_BYTES; ++offset) {
        const int high = nibble(input[offset * 2]);
        const int low = nibble(input[offset * 2 + 1]);
        if (high < 0 || low < 0) {
            OPENSSL_cleanse(secret, SECRET_BYTES);
            return 0;
        }
        secret[offset] = (unsigned char)(high * 16 + low);
    }
    return 1;
}

EVP_PKEY *issuer_from_hex(const char input[KEY_HEX_CAPACITY])
{
    unsigned char seed[SECRET_BYTES];
    EVP_PKEY *key = secret_from_hex(input, seed)
        ? EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed)) : NULL;
    OPENSSL_cleanse(seed, sizeof(seed));
    return key;
}

static void hex(const unsigned char *bytes, size_t length, char *output)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[2 * i] = digits[bytes[i] >> 4];
        output[2 * i + 1] = digits[bytes[i] & 15];
    }
    output[2 * length] = '\0';
}

int issuer_public_key(const EVP_PKEY *key, char output[KEY_HEX_CAPACITY])
{
    unsigned char public_key[32];
    size_t length = sizeof(public_key);
    const int ok = key && EVP_PKEY_get_raw_public_key(key, public_key, &length) == 1 &&
                   length == sizeof(public_key);
    if (ok) {
        hex(public_key, length, output);
    }
    return ok;
}

int issuer_envelope(EVP_PKEY *key, const char *receipt, int version, char output[ENVELOPE_CAPACITY])
{
    unsigned char message[RECEIPT_CAPACITY + 20];
    const int message_length = snprintf((char *)message, sizeof(message), "Repair Receipt v%d\n%s",
                                        version, receipt);
    if (message_length < 0 || (size_t)message_length >= sizeof(message)) {
        return 0;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char signature[64];
    size_t length = sizeof(signature);
    const int ok = key && context &&
                   EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1 &&
                   EVP_DigestSign(context, signature, &length, message, (size_t)message_length) == 1 &&
                   length == sizeof(signature);
    EVP_MD_CTX_free(context);
    if (!ok) {
        return 0;
    }
    char proof[SIGNATURE_CAPACITY];
    hex(signature, length, proof);
    const int size = snprintf(output, ENVELOPE_CAPACITY,
                              "{\"format\":\"repair-receipt/v%d\",\"claim\":%s,\"signature\":\"%s\"}",
                              version, receipt, proof);
    return size > 0 && size < ENVELOPE_CAPACITY;
}
