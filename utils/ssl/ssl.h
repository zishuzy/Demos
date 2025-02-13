#ifndef __UTILS_SSL_SSL_H__
#define __UTILS_SSL_SSL_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 设置错误码，合并 errno 和 ssl 到 e64 中
 *
 * @param e     errno 错误码
 * @param e64   输出错误码
 */
void ssl_set_error(uint32_t e, uint64_t *e64);

/**
 * @brief 从 e64 中获取错误码
 *
 * @param e64   输入错误码
 * @param e_no  输出 errno 错误码
 * @param e_ssl 输出 ssl 错误码
 */
void ssl_get_error(uint64_t e64, uint32_t *e_no, uint32_t *e_ssl);

/**
 * @brief 将错误码转换为字符串
 *
 * @param e     错误码
 * @param buf   缓冲区
 * @param len   缓冲区长度
 */
void ssl_error_string_n(uint64_t e, char *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* __UTILS_SSL_SSL_H__ */
