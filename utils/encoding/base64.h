#ifndef __ENCODING_C_BASE64_H__
#define __ENCODING_C_BASE64_H__

#include <stdint.h>
#include <stddef.h>

#define BASE64_ENCODED_LEN(l) (((l + 2) / 3) * 4)
#define BASE64_DECODED_LEN(l) (((l + 3) / 4) * 3)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief base64 编码
 *
 * @param src       源数据
 * @param src_len   源数据长度
 * @param dst       目标数据（需要调用者自己 free）
 * @param dst_len   目标数据长度
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int base64_encode(const uint8_t *src, size_t src_len, char **dst, size_t *dst_len);

/**
 * @brief base64 url 编码
 *
 * @param src       源数据
 * @param src_len   源数据长度
 * @param dst       目标数据（需要调用者自己 free）
 * @param dst_len   目标数据长度
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int base64_encode_url(const uint8_t *src, size_t src_len, char **dst, size_t *dst_len);

/**
 * @brief base64 解码
 *
 * @param src       源数据
 * @param src_len   源数据长度
 * @param dst       目标数据（需要调用者自己 free）
 * @param dst_len   目标数据长度
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int base64_decode(const char *src, size_t src_len, uint8_t **dst, size_t *dst_len);

/**
 * @brief base64 url 解码
 *
 * @param src       源数据
 * @param src_len   源数据长度
 * @param dst       目标数据（需要调用者自己 free）
 * @param dst_len   目标数据长度
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int base64_decode_url(const char *src, size_t src_len, uint8_t **dst, size_t *dst_len);

#ifdef __cplusplus
}
#endif

#endif /* __ENCODING_C_BASE64_H__ */
