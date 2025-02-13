/**
 * @file symm.h
 * @author zishu (zishuzy@gmail.com)
 * @brief 对称加密相关操作
 * @version 0.1
 * @date 2025-01-16
 *
 * @copyright Copyright (c) 2025
 *
 */
#ifndef __UTILS_SSL_SYMM_H__
#define __UTILS_SSL_SYMM_H__

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssl_symm_crypt ssl_symm_crypt_t;

/**
 * @brief 创建一个对称加密对象
 *
 * @param cipher_type   密钥算法
 * @param key           密钥
 * @param key_len       密钥长度
 * @param iv            初始化向量
 * @param iv_len        初始化向量长度
 * @param enc           加密还是解密
 * @param error         错误码
 * @return ssl_symm_crypt_t* 对称加密对象
 */
ssl_symm_crypt_t *ssl_symm_crypt_new(const EVP_CIPHER *cipher_type, const uint8_t *key,
                                     size_t key_len, const uint8_t *iv, size_t iv_len,
                                     int enc, uint64_t *error);

/**
 * @brief 释放一个对称加密对象
 *
 * @param crypt 对称加密对象
 */
void ssl_symm_crypt_free(ssl_symm_crypt_t *crypt);

/**
 * @brief 获取对称加密对象的块大小
 *
 * @param crypt 对称加密对象
 * @return int  块大小，返回 -1 表示出错
 */
int ssl_symm_block_size(ssl_symm_crypt_t *crypt);

/**
 * @brief 获取对称加密对象的输出块大小
 *
 * @param crypt 对称加密对象
 * @return int  输出块大小，返回 -1 表示出错
 */
int ssl_symm_block_out_size(ssl_symm_crypt_t *crypt);

/**
 * @brief 对称加密块
 *
 * @param crypt   对称加密对象
 * @param src     输入数据
 * @param src_len 输入数据长度
 * @param last    是否是最后一个块
 * @param dst     输出数据（外部提供）
 * @param dst_len 输出数据长度
 * @param error   错误码
 * @return int    加密后的数据长度，返回 -1 表示出错
 */
int ssl_symm_encrypt_block(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                           int last, uint8_t *dst, size_t dst_len, uint64_t *error);

/**
 * @brief 对称解密块
 *
 * @param crypt   对称加密对象
 * @param src     输入数据
 * @param src_len 输入数据长度
 * @param last    是否是最后一个块
 * @param dst     输出数据（外部提供）
 * @param dst_len 输出数据长度
 * @param error   错误码
 * @return int    解密后的数据长度，返回 -1 表示出错
 */
int ssl_symm_decrypt_block(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                           int last, uint8_t *dst, size_t dst_len, uint64_t *error);

/**
 * @brief 对称加密，和 ssl_symm_encrypt_block 区别是，本接口会自动循环加密
 *
 * @param crypt   对称加密对象
 * @param src     输入数据
 * @param src_len 输入数据长度
 * @param dst     输出数据（内部创建，外部释放）
 * @param error   错误码
 * @return int    加密后的数据长度，返回 -1 表示出错
 */
int ssl_symm_encrypt(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                     uint8_t **dst, uint64_t *error);

/**
 * @brief 对称加密，和 ssl_symm_encrypt 区别是，本接口传入 ssl 原始参数
 *
 * @param cipher_type 密钥算法
 * @param key         密钥
 * @param key_len     密钥长度
 * @param iv          初始化向量
 * @param iv_len      初始化向量长度
 * @param src         输入数据
 * @param src_len     输入数据长度
 * @param dst         输出数据（内部创建，外部释放）
 * @param error       错误码
 * @return int        加密后的数据长度，返回 -1 表示出错
 */
int ssl_symm_encrypt2(const EVP_CIPHER *cipher_type, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *src, int src_len,
                      uint8_t **dst, uint64_t *error);

/**
 * @brief 对称解密，和 ssl_symm_decrypt_block 区别是，本接口会自动循环解密
 *
 * @param crypt   对称加密对象
 * @param src     输入数据
 * @param src_len 输入数据长度
 * @param dst     输出数据（内部创建，外部释放）
 * @param error   错误码
 * @return int    解密后的数据长度，返回 -1表示出错
 */
int ssl_symm_decrypt(ssl_symm_crypt_t *crypt, const uint8_t *src, int src_len,
                     uint8_t **dst, uint64_t *error);

/**
 * @brief 对称解密，和 ssl_symm_decrypt 区别是，本接口传入 ssl 原始参数
 *
 * @param cipher_type 密钥算法
 * @param key         密钥
 * @param key_len     密钥长度
 * @param iv          初始化向量
 * @param iv_len      初始化向量长度
 * @param src         输入数据
 * @param src_len     输入数据长度
 * @param dst         输出数据（内部创建，外部释放）
 * @param error       错误码
 * @return int
 */
int ssl_symm_decrypt2(const EVP_CIPHER *cipher_type, const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len, const uint8_t *src, int src_len,
                      uint8_t **dst, uint64_t *error);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_SSL_SYMM_H__ */
