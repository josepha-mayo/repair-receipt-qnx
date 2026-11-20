#include "sealed_recording.h"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { NONCE_BYTES = 12, TAG_BYTES = 16, MAX_STAGED_BYTES = 4 * 1024 * 1024 + 1 };
static const unsigned char domain[] = "Repair Receipt CSV stage v1";

static int decrypt(const unsigned char *sealed, int length, unsigned char *plaintext,
                   const unsigned char key[SECRET_BYTES])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char final[EVP_MAX_BLOCK_LENGTH];
    int amount, extra;
    const int verified = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, sealed) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &amount, domain, sizeof(domain) - 1) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext, &amount, sealed + NONCE_BYTES, length) == 1 &&
        amount == length &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, (void *)(sealed + NONCE_BYTES + length)) == 1 &&
        EVP_DecryptFinal_ex(ctx, final, &extra) == 1 && extra == 0;
    OPENSSL_cleanse(final, sizeof(final));
    EVP_CIPHER_CTX_free(ctx);
    return verified;
}

FILE *open_sealed_recording(const char *path, const unsigned char key[SECRET_BYTES])
{
    FILE *source = fopen(path, "rb");
    if (!source) {
        return NULL;
    }
    struct stat info;
    if (fstat(fileno(source), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size <= NONCE_BYTES + TAG_BYTES || info.st_size > MAX_STAGED_BYTES + NONCE_BYTES + TAG_BYTES) {
        fclose(source);
        return NULL;
    }
    const size_t size = (size_t)info.st_size;
    const int length = (int)(size - NONCE_BYTES - TAG_BYTES);
    unsigned char *sealed = malloc(size);
    const int loaded = sealed && fread(sealed, 1, size, source) == size && fgetc(source) == EOF && !ferror(source);
    fclose(source);
    if (!loaded) {
        free(sealed);
        return NULL;
    }

    const int fd = shm_open(SHM_ANON, O_RDWR, 0600);
    unsigned char *plaintext = MAP_FAILED;
    if (fd >= 0 && ftruncate(fd, length) == 0) {
        plaintext = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    FILE *recording = NULL;
    if (plaintext != MAP_FAILED) {
        if (decrypt(sealed, length, plaintext, key)) {
            recording = fdopen(fd, "rb");
        }
        if (!recording) {
            OPENSSL_cleanse(plaintext, length);
        }
        munmap(plaintext, length);
    }
    if (fd >= 0 && !recording) {
        close(fd);
    }
    free(sealed);
    return recording;
}
