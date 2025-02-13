#include "rsa.h"
#include "ssl.h"

static void reverse_data(uint8_t *data, size_t len)
{
    int i;
    for (i = 0; i < len / 2; i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = tmp;
    }
}

int rsa_generate_pkey(int bits, EVP_PKEY **pkey, uint64_t *error)
{
    EVP_PKEY_CTX *ctx = NULL;
    int rc = -1;

    do {
        if (pkey == NULL) {
            ssl_set_error(EINVAL, error);
            break;
        }

        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_keygen(ctx, pkey) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        rc = 0;
    } while (0);

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return rc;
}

void rsa_free_pkey(EVP_PKEY *pkey)
{
    EVP_PKEY_free(pkey);
}

int rsa_pub_key_to_file(EVP_PKEY *pub_key, const char *filename, uint64_t *error)
{
    FILE *fp = NULL;
    int res = -1;

    do {
        if (!pub_key || !filename) {
            ssl_set_error(EINVAL, error);
            break;
        }

        fp = fopen(filename, "wb");
        if (!fp) {
            ssl_set_error(errno, error);
            break;
        }

        if (PEM_write_PUBKEY(fp, pub_key) != 1) {
            ssl_set_error(0, error);
            break;
        }

        res = 0;
    } while (0);

    if (fp) {
        fclose(fp);
    }
    return res;
}

int rsa_pri_key_to_file(EVP_PKEY *pri_key, const char *filename, uint64_t *error)
{
    FILE *fp = NULL;
    int res = -1;

    do {
        if (!pri_key || !filename) {
            ssl_set_error(EINVAL, error);
            break;
        }

        fp = fopen(filename, "wb");
        if (!fp) {
            ssl_set_error(errno, error);
            break;
        }

        if (PEM_write_PrivateKey(fp, pri_key, NULL, NULL, 0, NULL, NULL) != 1) {
            ssl_set_error(0, error);
            break;
        }

        res = 0;
    } while (0);

    if (fp) {
        fclose(fp);
    }
    return res;
}

int rsa_load_pub_key_from_file(const char *filename, EVP_PKEY **pkey_out, uint64_t *error)
{
    FILE *fp = NULL;
    int res = -1;

    do {
        EVP_PKEY *pkey = NULL;
        if (!filename || !pkey_out) {
            ssl_set_error(EINVAL, error);
            break;
        }

        fp = fopen(filename, "rb");
        if (!fp) {
            ssl_set_error(errno, error);
            break;
        }
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        if (pkey == NULL) {
            ssl_set_error(0, error);
            break;
        }

        *pkey_out = pkey;
        res = 0;
    } while (0);

    return res;
}

int rsa_load_pri_key_from_file(const char *filename, EVP_PKEY **pkey_out, uint64_t *error)
{
    FILE *fp = NULL;
    int res = -1;

    do {
        EVP_PKEY *pkey = NULL;
        if (!filename || !pkey_out) {
            ssl_set_error(EINVAL, error);
            break;
        }
        fp = fopen(filename, "rb");
        if (!fp) {
            ssl_set_error(errno, error);
            break;
        }
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        if (pkey == NULL) {
            ssl_set_error(0, error);
            break;
        }

        *pkey_out = pkey;
        res = 0;
    } while (0);

    if (fp) {
        fclose(fp);
    }

    return res;
}

int rsa_pub_key_to_base64(EVP_PKEY *pkey, char **base64_out, uint64_t *error)
{
    BIO *bio = NULL;
    int res = -1;

    do {
        BUF_MEM *bptr = NULL;
        int len = 0;

        if (!pkey || !base64_out) {
            ssl_set_error(EINVAL, error);
            break;
        }
        bio = BIO_new(BIO_s_mem());
        if (!bio) {
            ssl_set_error(0, error);
            break;
        }

        if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
            ssl_set_error(0, error);
            break;
        }

        BIO_get_mem_ptr(bio, &bptr);
        len = bptr->length;

        *base64_out = (char *)malloc(len + 1);
        if (*base64_out == NULL) {
            ssl_set_error(ENOMEM, error);
            break;
        }
        memcpy(*base64_out, bptr->data, len);
        (*base64_out)[len] = '\0';

        res = 0;
    } while (0);

    if (bio) {
        BIO_free(bio);
    }

    return res;
}

int rsa_base64_to_pub_key(const char *base64, EVP_PKEY **pkey_out, uint64_t *error)
{
    BIO *bio = NULL;
    int res = -1;

    do {
        EVP_PKEY *pkey = NULL;
        if (!base64 || !pkey_out) {
            ssl_set_error(EINVAL, error);
            break;
        }

        bio = BIO_new_mem_buf(base64, -1);
        if (!bio) {
            ssl_set_error(0, error);
            break;
        }

        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (!pkey) {
            ssl_set_error(0, error);
            break;
        }

        *pkey_out = pkey;
        res = 0;
    } while (0);

    if (bio) {
        BIO_free(bio);
    }

    return res;
}

int rsa_encrypt(EVP_PKEY *pub_key, const uint8_t *src, size_t src_len, int reverse,
                uint8_t **dst, size_t *dst_len, uint64_t *error)
{
    EVP_PKEY_CTX *ctx = NULL;
    char *buf = NULL;
    int res = -1;
    size_t max_len = (EVP_PKEY_size(pub_key) - RSA_PKCS1_PADDING_SIZE);

    if (!pub_key || !src || !dst || !dst_len) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    if (src_len > max_len) {
        ssl_set_error(ERANGE, error);
        return -1;
    }

    do {
        int key_size = 0;
        uint8_t *out = NULL;
        size_t out_len = 0;

        ctx = EVP_PKEY_CTX_new(pub_key, NULL);
        if (!ctx) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_encrypt(ctx, NULL, &out_len, src, src_len) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        out = malloc(out_len);
        if (!out) {
            ssl_set_error(ENOMEM, error);
            break;
        }

        if (EVP_PKEY_encrypt(ctx, out, &out_len, src, src_len) <= 0) {
            free(out);
            ssl_set_error(0, error);
            break;
        }

        if (reverse) {
            reverse_data(out, out_len);
        }

        *dst = out;
        *dst_len = out_len;

        res = 0;
    } while (0);

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return res;
}

int rsa_decrypt(EVP_PKEY *pri_key, const uint8_t *src, size_t src_len, int reverse,
                uint8_t **dst, size_t *dst_len, uint64_t *error)
{

    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *in = NULL;
    char *buf = NULL;
    int res = -1;

    if (!pri_key || !src || !src_len || !dst || !dst_len) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    if (src_len > EVP_PKEY_size(pri_key)) {
        ssl_set_error(ERANGE, error);
        return -1;
    }

    do {
        int key_size = 0;
        uint8_t *out = NULL;
        size_t out_len = 0;

        ctx = EVP_PKEY_CTX_new(pri_key, NULL);
        if (!ctx) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        // XXX: 这里不管是否需要反转，都分配了内存，是为了让代码好看，
        // 在不需要反转时完全可以不分配内存的。
        in = malloc(src_len);
        if (!in) {
            ssl_set_error(ENOMEM, error);
            break;
        }
        memcpy(in, src, src_len);

        if (reverse) {
            reverse_data(in, src_len);
        }

        if (EVP_PKEY_decrypt(ctx, NULL, &out_len, in, src_len) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        out = malloc(out_len);
        if (!out) {
            ssl_set_error(ENOMEM, error);
            break;
        }

        if (EVP_PKEY_decrypt(ctx, out, &out_len, src, src_len) <= 0) {
            free(out);
            ssl_set_error(0, error);
            break;
        }

        *dst = out;
        *dst_len = out_len;
        res = 0;
    } while (0);
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (in) {
        free(in);
    }

    return res;
}

size_t rsa_get_encrypt_len(EVP_PKEY *pub_key, size_t data_len)
{
    size_t key_len = EVP_PKEY_size(pub_key);
    size_t max_block_size = key_len - RSA_PKCS1_PADDING_SIZE;
    return (data_len / max_block_size + (data_len % max_block_size != 0)) * key_len;
}

static int encrypt_block(EVP_PKEY *pub_key, EVP_PKEY_CTX *ctx, const uint8_t *src,
                         size_t src_len, int reverse, uint8_t **dst, size_t *dst_len,
                         uint64_t *error)
{
    size_t max_block_size = EVP_PKEY_size(pub_key) - RSA_PKCS1_PADDING_SIZE;
    size_t max_enc_len = rsa_get_encrypt_len(pub_key, src_len);
    uint8_t *enc = NULL;
    size_t enc_len = 0;
    size_t offset = 0;

    enc = (uint8_t *)calloc(1, max_enc_len);
    if (!enc) {
        ssl_set_error(ENOMEM, error);
        return -1;
    }
    while (offset < src_len) {
        size_t remain_size = src_len - offset;
        size_t block_size = remain_size < max_block_size ? remain_size : max_block_size;
        const uint8_t *block_data = src + offset;
        uint8_t *out_data = enc + enc_len;
        size_t out_len = 0;

        if (EVP_PKEY_encrypt(ctx, NULL, &out_len, block_data, block_size) <= 0) {
            ssl_set_error(0, error);
            free(enc);
            return -1;
        }
        if (enc_len + out_len > max_enc_len) {
            ssl_set_error(ERANGE, error);
            free(enc);
            return -1;
        }
        if (EVP_PKEY_encrypt(ctx, out_data, &out_len, block_data, block_size) <= 0) {
            ssl_set_error(0, error);
            free(enc);
            return -1;
        }
        if (reverse) {
            reverse_data(out_data, out_len);
        }

        enc_len += out_len;
        offset += block_size;
    }

    *dst = enc;
    *dst_len = enc_len;

    return 0;
}

static int decrypt_block(EVP_PKEY *pri_key, EVP_PKEY_CTX *ctx, const uint8_t *src,
                         size_t src_len, int reverse, uint8_t **dst, size_t *dst_len,
                         uint64_t *error)
{
    size_t block_size = EVP_PKEY_size(pri_key);
    uint8_t *block_data = NULL;
    uint8_t *dec = NULL;
    size_t dec_len = 0;
    size_t offset = 0;

    dec = (uint8_t *)calloc(1, src_len); // 解密后大小一定小于源数据
    if (!dec) {
        ssl_set_error(ENOMEM, error);
        return -1;
    }
    block_data = (uint8_t *)calloc(1, block_size);
    if (!block_data) {
        ssl_set_error(ENOMEM, error);
        free(dec);
        return -1;
    }

    while (offset + block_size <= src_len) {
        uint8_t *out_data = dec + dec_len;
        size_t out_len = 0;

        memcpy(block_data, src + offset, block_size);
        if (reverse) {
            reverse_data(block_data, block_size);
        }

        if (EVP_PKEY_decrypt(ctx, NULL, &out_len, block_data, block_size) <= 0) {
            ssl_set_error(0, error);
            free(dec);
            return -1;
        }

        if (dec_len + out_len > src_len) {
            ssl_set_error(ERANGE, error);
            free(dec);
            return -1;
        }

        if (EVP_PKEY_decrypt(ctx, out_data, &out_len, block_data, block_size) <= 0) {
            ssl_set_error(0, error);
            free(dec);
            return -1;
        }

        dec_len += out_len;
        offset += block_size;
    }

    *dst = dec;
    *dst_len = dec_len;

    if (block_data) {
        free(block_data);
    }

    return 0;
}

int rsa_encrypt_large(EVP_PKEY *pub_key, const uint8_t *src, size_t src_len, int reverse,
                      uint8_t **dst, size_t *dst_len, uint64_t *error)
{
    EVP_PKEY_CTX *ctx = NULL;
    char *buf = NULL;
    int res = -1;

    if (!pub_key || !src || !dst || !dst_len) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    do {
        int key_size = 0;
        uint8_t *out = NULL;
        size_t out_len = 0;

        ctx = EVP_PKEY_CTX_new(pub_key, NULL);
        if (!ctx) {
            ssl_set_error(0, error);
            break;
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            ssl_set_error(0, error);
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        if (encrypt_block(pub_key, ctx, src, src_len, reverse, &out, &out_len, error) <
            0) {
            break;
        }

        *dst = out;
        *dst_len = out_len;

        res = 0;
    } while (0);

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return res;
}

int rsa_decrypt_large(EVP_PKEY *pri_key, const uint8_t *src, size_t src_len, int reverse,
                      uint8_t **dst, size_t *dst_len, uint64_t *error)
{
    EVP_PKEY_CTX *ctx = NULL;
    char *buf = NULL;
    int res = -1;

    if (!pri_key || !src || !dst || !dst_len) {
        ssl_set_error(EINVAL, error);
        return -1;
    }

    do {
        int key_size = 0;
        uint8_t *out = NULL;
        size_t out_len = 0;

        ctx = EVP_PKEY_CTX_new(pri_key, NULL);
        if (!ctx) {
            ssl_set_error(0, error);
            break;
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            ssl_set_error(0, error);
            break;
        }

        if (decrypt_block(pri_key, ctx, src, src_len, reverse, &out, &out_len, error) <
            0) {
            break;
        }

        *dst = out;
        *dst_len = out_len;

        res = 0;
    } while (0);

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return res;
}
