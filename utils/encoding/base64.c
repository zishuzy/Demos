#include "base64.h"

#include <stdlib.h>

#include "utils/log/log.h"

static const char table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char table_url[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int encode(const char *base64_table, int pad, const uint8_t *src, int src_len,
                  char *dst)
{
    uint32_t ac = 0;
    int bits = 0;
    int i;
    char *cp = dst;

    for (i = 0; i < src_len; i++) {
        ac = (ac << 8) | src[i];
        bits += 8;
        do {
            bits -= 6;
            *cp++ = base64_table[(ac >> bits) & 0x3f];
        } while (bits >= 6);
    }
    if (bits) {
        *cp++ = base64_table[(ac << (6 - bits)) & 0x3f];
        bits -= 6;
    }
    if (pad) {
        while (bits < 0) {
            *cp++ = '=';
            bits += 2;
        }
    }
    return cp - dst;
}

static int decode(const char *base64_table, const char *src, int src_len, uint8_t *dst)
{
    uint32_t ac = 0;
    int bits = 0;
    int i;
    uint8_t *bp = dst;

    for (i = 0; i < src_len; i++) {
        const char *p = strchr(base64_table, src[i]);

        if (src[i] == '=') {
            ac = (ac << 6);
            bits += 6;
            if (bits >= 8)
                bits -= 8;
            continue;
        }
        if (p == NULL || src[i] == 0)
            return -1;
        ac = (ac << 6) | (p - base64_table);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            *bp++ = (uint8_t)(ac >> bits);
        }
    }
    if (ac & ((1 << bits) - 1))
        return -1;
    return bp - dst;
}

int base64_encode(const uint8_t *src, size_t src_len, char **dst, size_t *dst_len)
{
    int rc = -1;

    if (!src || !dst || !dst_len) {
        LOG_ERROR("Invalid argument!");
        return -1;
    }

    do {
        size_t encoded_len = BASE64_ENCODED_LEN(src_len);
        char *encoded = malloc(encoded_len + 1);
        if (!encoded) {
            LOG_ERROR("Failed to allocate memory!");
            break;
        }
        encoded_len = encode(table, 1, src, src_len, encoded);
        if (encoded_len < 0) {
            LOG_ERROR("Failed to encode!");
            free(encoded);
            break;
        }
        encoded[encoded_len] = '\0';
        *dst = encoded;
        *dst_len = encoded_len;
        rc = 0;
    } while (0);

    return rc;
}

int base64_encode_url(const uint8_t *src, size_t src_len, char **dst, size_t *dst_len)
{
    int rc = -1;

    if (!src || !dst || !dst_len) {
        LOG_ERROR("Invalid argument!");
        return -1;
    }

    do {
        size_t encoded_len = BASE64_ENCODED_LEN(src_len);
        char *encoded = malloc(encoded_len + 1);
        if (!encoded) {
            LOG_ERROR("Failed to allocate memory!");
            break;
        }
        encoded_len = encode(table_url, 0, src, src_len, encoded);
        if (encoded_len < 0) {
            LOG_ERROR("Failed to encode!");
            free(encoded);
            break;
        }
        encoded[encoded_len] = '\0';
        *dst = encoded;
        *dst_len = encoded_len;
        rc = 0;
    } while (0);

    return rc;
}

int base64_decode(const char *src, size_t src_len, uint8_t **dst, size_t *dst_len)
{
    int rc = -1;

    if (!src || !dst || !dst_len) {
        LOG_ERROR("Invalid argument!");
        return -1;
    }

    do {
        size_t decoded_len = src_len;
        uint8_t *decoded = malloc(decoded_len + 1);
        if (!decoded) {
            LOG_ERROR("Failed to allocate memory!");
            break;
        }
        decoded_len = decode(table, src, src_len, decoded);
        if (decoded_len < 0) {
            LOG_ERROR("Failed to encode!");
            free(decoded);
            break;
        }
        decoded[decoded_len] = '\0';
        *dst = decoded;
        *dst_len = decoded_len;

        rc = 0;
    } while (0);

    return rc;
}

int base64_decode_url(const char *src, size_t src_len, uint8_t **dst, size_t *dst_len)
{
    int rc = -1;

    if (!src || !dst || !dst_len) {
        LOG_ERROR("Invalid argument!");
        return -1;
    }

    do {
        size_t decoded_len = src_len;
        uint8_t *decoded = malloc(decoded_len + 1);
        if (!decoded) {
            LOG_ERROR("Failed to allocate memory!");
            break;
        }
        decoded_len = decode(table_url, src, src_len, decoded);
        if (decoded_len < 0) {
            LOG_ERROR("Failed to encode!");
            free(decoded);
            break;
        }
        decoded[decoded_len] = '\0';
        *dst = decoded;
        *dst_len = decoded_len;

        rc = 0;
    } while (0);

    return rc;
}