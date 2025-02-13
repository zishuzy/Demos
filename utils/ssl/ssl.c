#include "ssl.h"
#include <string.h>

#include <openssl/err.h>

void ssl_set_error(uint32_t e, uint64_t *e64)
{
    if (e64 == NULL) {
        return;
    }
    *e64 = ERR_get_error() & 0xFFFFFFFF;
    if (e != 0) {
        *e64 |= ((uint64_t)e << 32);
    }
}

void ssl_get_error(uint64_t e64, uint32_t *e_no, uint32_t *e_ssl)
{
    if (e_ssl)
        *e_ssl = (uint32_t)(e64 & 0xFFFFFFFF);
    if (e_no)
        *e_no = (uint32_t)(e64 >> 32);
}

void ssl_error_string_n(uint64_t e, char *buf, size_t len)
{
    uint32_t e_no, e_ssl;
    int out_len = 0;
    ssl_get_error(e, &e_no, &e_ssl);
    if (e_no != 0) {
        out_len = snprintf(buf, len - 1, "%s", strerror(e_no));
    }
    if (e_ssl != 0) {
        out_len += snprintf(buf + out_len, len - out_len - 1, ", ");
        ERR_error_string_n(e_ssl, buf + out_len, len - out_len - 1);
    }
}
