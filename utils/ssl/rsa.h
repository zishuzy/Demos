#ifndef __SSL_RSA__
#define __SSL_RSA__

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 生成 RSA 密钥对
 *
 * @param bits      密钥长度
 * @param EVP_PKEY  生成的密钥对
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_generate_pkey(int bits, EVP_PKEY **pkey, uint64_t *error);

/**
 * @brief 释放密钥
 *
 * @param pkey
 */
void rsa_free_pkey(EVP_PKEY *pkey);

/**
 * @brief 将公钥写入文件
 *
 * @param pub_key   公钥
 * @param filename  文件路径
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_pub_key_to_file(EVP_PKEY *pub_key, const char *filename, uint64_t *error);

/**
 * @brief 将私钥写入文件
 *
 * @param pri_key   私钥
 * @param filename  文件路径
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_pri_key_to_file(EVP_PKEY *pri_key, const char *filename, uint64_t *error);
/**
 * @brief 从公钥文件中加载公钥
 *
 * @param filename  文件路径
 * @param pkey_out  公钥
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_load_pub_key_from_file(const char *filename, EVP_PKEY **pkey_out,
                               uint64_t *error);

/**
 * @brief 从私钥文件中加载私钥
 *
 * @param filename  文件路径
 * @param pkey_out  私钥
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_load_pri_key_from_file(const char *filename, EVP_PKEY **pkey_out,
                               uint64_t *error);

/**
 * @brief 将公钥转换为 base64
 *
 * @param pkey          公钥
 * @param base64_out    base64 公钥
 * @param error         错误码
 * @return int          On success, 0 is returned. On error, -1 is returned.
 */
int rsa_pub_key_to_base64(EVP_PKEY *pkey, char **base64_out, uint64_t *error);

/**
 * @brief 将 base64 转换为公钥
 *
 * @param base64    base64 公钥
 * @param pkey_out  公钥
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_base64_to_pub_key(const char *base64, EVP_PKEY **pkey_out, uint64_t *error);

/**
 * @brief RSA 加密（RSA_PKCS1_PADDING 填充方式）
 *
 * @param pub_key   公钥
 * @param src       源数据
 * @param src_len   源数据长度
 * @param reverse   反转加密块（为兼容 windows）
 * @param dst       目标数据（需要用户自己释放）
 * @param dst_len   目标数据长度
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_encrypt(EVP_PKEY *pub_key, const uint8_t *src, size_t src_len, int reverse,
                uint8_t **dst, size_t *dst_len, uint64_t *error);

/**
 * @brief RSA 解密（RSA_PKCS1_PADDING 填充方式）
 *
 * @param pri_key   私钥
 * @param src       源数据
 * @param src_len   源数据长度
 * @param reverse   反转加密块（为兼容 windows）
 * @param dst       目标数据（需要用户自己释放）
 * @param dst_len   目标数据长度
 * @param error     错误码
 * @return int      On success, 0 is returned. On error, -1 is returned.
 */
int rsa_decrypt(EVP_PKEY *pri_key, const uint8_t *src, size_t src_len, int reverse,
                uint8_t **dst, size_t *dst_len, uint64_t *error);

/**
 * @brief 获取加密（RSA_PKCS1_PADDING）后的数据长度（循环加密）
 *
 * @param pub_key   公钥
 * @param src_len   源数据长度
 * @return size_t   加密后的数据长度
 */
size_t rsa_get_encrypt_len(EVP_PKEY *pub_key, size_t src_len);

/**
 * @brief RSA 加密（RSA_PKCS1_PADDING 填充方式），如果数据太大，会循环加密
 *
 * @param pub_key   公钥
 * @param src       源数据
 * @param src_len   源数据长度
 * @param reverse   反转加密块（为兼容 windows）
 * @param dst       目标数据（需要用户自己释放）
 * @param dst_len   目标数据长度
 * @param error     错误码
 * @return int
 */
int rsa_encrypt_large(EVP_PKEY *pub_key, const uint8_t *src, size_t src_len, int reverse,
                      uint8_t **dst, size_t *dst_len, uint64_t *error);

/**
 * @brief RSA 解密（RSA_PKCS1_PADDING 填充方式），如果数据太大，会循环解密
 *
 * @param pri_key   私钥
 * @param src       源数据
 * @param src_len   源数据长度
 * @param reverse   反转加密块（为兼容 windows）
 * @param dst       目标数据（需要用户自己释放）
 * @param dst_len   目标数据长度
 * @param error     错误码
 * @return int
 */
int rsa_decrypt_large(EVP_PKEY *pri_key, const uint8_t *src, size_t src_len, int reverse,
                      uint8_t **dst, size_t *dst_len, uint64_t *error);

#ifdef __cplusplus
}
#endif

#endif /* __SSL_RSA__ */
