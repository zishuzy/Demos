#include "symm.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "ssl.h"

struct ssl_symm_crypt {
    const EVP_CIPHER *cipher_type;
    const uint8_t *key;
    size_t key_len;
    const uint8_t *iv;
    size_t iv_len;
    EVP_CIPHER_CTX *ctx;
    int block_size;
    int block_out_size;
};

ssl_symm_crypt_t *ssl_symm_crypt_new(const EVP_CIPHER *cipher_type, const uint8_t *key,
                                     size_t key_len, const uint8_t *iv, size_t iv_len,
                                     int enc, uint64_t *error)
{
    EVP_CIPHER_CTX *ctx = NULL;
    ssl_symm_crypt_t *crypt = NULL;
    int ret = -1;

    do {
        int block_size;

        if (!cipher_type || !key) {
            ssl_set_error(EINVAL, error);
            break;
        }
        if (key_len != EVP_CIPHER_get_key_length(cipher_type)) {
            ssl_set_error(EINVAL, error);
            break;
        }
        if (iv && iv_len != EVP_CIPHER_get_iv_length(cipher_type)) {
            ssl_set_error(EINVAL, error);
            break;
        }

        block_size = EVP_CIPHER_get_block_size(cipher_type);
        if (block_size <= 0) {
            ssl_set_error(EINVAL, error);
            break;
        }
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            ssl_set_error(0, error);
            break;
        }

        if (enc) {
            if (EVP_EncryptInit(ctx, cipher_type, key, iv) <= 0) {
                ssl_set_error(0, error);
                break;
            }
        } else {
            if (EVP_DecryptInit(ctx, cipher_type, key, iv) <= 0) {
                ssl_set_error(0, error);
                break;
            }
        }

        crypt = calloc(1, sizeof(ssl_symm_crypt_t));
        if (!crypt) {
            ssl_set_error(ENOMEM, error);
            break;
        }

        crypt->cipher_type = cipher_type;
        crypt->key = key;
        crypt->iv = iv;
        crypt->ctx = ctx;
        if (enc) {
            crypt->block_size = block_size;
            crypt->block_out_size = 2 * block_size;
        } else {
            crypt->block_size = 2 * block_size;
            crypt->block_out_size = 4 * block_size;
        }

        ret = 0;
    } while (0);

    if (ret != 0) {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
        if (crypt) {
            free(crypt);
        }
    }

    return ret == 0 ? crypt : NULL;
}

void ssl_symm_crypt_free(ssl_symm_crypt_t *crypt)
{
    if (!crypt) {
        return;
    }
    if (crypt->ctx) {
        EVP_CIPHER_CTX_free(crypt->ctx);
    }
    free(crypt);
}

int ssl_symm_block_size(ssl_symm_crypt_t *crypt)
{
    if (!crypt) {
        return -1;
    }
    return crypt->block_size;
}

int ssl_symm_block_out_size(ssl_symm_crypt_t *crypt)
{
    if (!crypt) {
        return -1;
    }
    return crypt->block_out_size;
}

int ssl_symm_encrypt_block(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                           int last, uint8_t *dst, size_t dst_len, uint64_t *error)
{
    if (!crypt) {
        ssl_set_error(EINVAL, error);
        return -1;
    }
    int block_size = crypt->block_size;
    int block_out_size = crypt->block_out_size;
    int len = -1;

    if (!block_size || !src || src_len < 0 || src_len > block_size || !dst ||
        dst_len < block_out_size) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    do {
        int outlen = 0;
        if (!EVP_EncryptUpdate(crypt->ctx, dst, &outlen, src, src_len)) {
            ssl_set_error(0, error);
            break;
        }

        if (last) {
            int tmplen = 0;
            if (1 != EVP_EncryptFinal_ex(crypt->ctx, dst + outlen, &tmplen)) {
                ssl_set_error(0, error);
                break;
            }
            outlen += tmplen;
        }

        len = outlen;
    } while (0);

    return len;
}

int ssl_symm_decrypt_block(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                           int last, uint8_t *dst, size_t dst_len, uint64_t *error)
{
    if (!crypt) {
        ssl_set_error(EINVAL, error);
        return -1;
    }
    int block_size = crypt->block_size;
    int block_dec_size = crypt->block_out_size;
    int len = -1;

    if (!block_size || !src || src_len < 0 || src_len > block_size || !dst ||
        dst_len < block_dec_size) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    do {
        int outlen = 0;
        if (!EVP_DecryptUpdate(crypt->ctx, dst, &outlen, src, src_len)) {
            ssl_set_error(0, error);
            break;
        }

        if (last) {
            int tmplen = 0;
            if (1 != EVP_DecryptFinal(crypt->ctx, dst + outlen, &tmplen)) {
                ssl_set_error(0, error);
                break;
            }
            outlen += tmplen;
        }

        len = outlen;
    } while (0);
    return len;
}

int ssl_symm_encrypt(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                     uint8_t **dst, uint64_t *error)
{
    int len = -1;

    if (!crypt || !src || src_len < 0 || !dst) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    do {
        int block_size = crypt->block_size;
        uint8_t *buff = NULL;
        int out_len = 0;
        int tmplen = 0;

        buff = calloc(1, src_len + block_size);
        if (!buff) {
            ssl_set_error(ENOMEM, error);
            break;
        }

        if (1 != EVP_EncryptUpdate(crypt->ctx, buff, &out_len, src, src_len)) {
            free(buff);
            ssl_set_error(0, error);
            break;
        }

        if (1 != EVP_EncryptFinal(crypt->ctx, buff + out_len, &tmplen)) {
            free(buff);
            ssl_set_error(0, error);
            break;
        }
        out_len += tmplen;

        *dst = buff;
        len = out_len;
    } while (0);

    return len;
}

int ssl_symm_encrypt2(const EVP_CIPHER *cipher_type, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *src, int src_len,
                      uint8_t **dst, uint64_t *error)
{
    ssl_symm_crypt_t *crypt =
        ssl_symm_crypt_new(cipher_type, key, key_len, iv, iv_len, 1, error);
    if (!crypt) {
        return -1;
    }
    int len = ssl_symm_encrypt(crypt, src, src_len, dst, error);
    ssl_symm_crypt_free(crypt);
    return len;
}

int ssl_symm_decrypt(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                     uint8_t **dst, uint64_t *error)
{
    int len = -1;

    if (!crypt || !src || src_len < 0 || !dst) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    do {
        int block_size = crypt->block_size;
        uint8_t *buff = NULL;
        int out_len = 0;
        int tmplen = 0;

        buff = calloc(1, src_len + block_size);
        if (!buff) {
            ssl_set_error(ENOMEM, error);
            break;
        }

        if (1 != EVP_DecryptUpdate(crypt->ctx, buff, &out_len, src, src_len)) {
            free(buff);
            ssl_set_error(0, error);
            break;
        }

        if (1 != EVP_DecryptFinal(crypt->ctx, buff + out_len, &tmplen)) {
            free(buff);
            ssl_set_error(0, error);
            break;
        }
        out_len += tmplen;

        *dst = buff;
        len = out_len;
    } while (0);

    return len;
}

int ssl_symm_decrypt2(const EVP_CIPHER *cipher_type, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *src, int src_len,
                      uint8_t **dst, uint64_t *error)
{
    ssl_symm_crypt_t *crypt =
        ssl_symm_crypt_new(cipher_type, key, key_len, iv, iv_len, 0, error);
    if (!crypt) {
        return -1;
    }
    int len = ssl_symm_decrypt(crypt, src, src_len, dst, error);
    ssl_symm_crypt_free(crypt);
    return len;
}
