#include "symm.h"
#include "ssl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

TEST(symm, crypt_new)
{
    {
        uint8_t key[32] = {0};
        uint8_t iv[16] = {0};
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        uint64_t error = 0;
        ssl_symm_crypt_t *aes_crypt = NULL;
        char errstr[1024] = {0};

        for (int i = 0; i < sizeof(key); i++) {
            key[i] = 'a' + i % 26;
        }
        for (int i = 0; i < sizeof(iv); i++) {
            iv[i] = 'a' + i % 26;
        }
        // 测试加密
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 1, &error);
        EXPECT_TRUE(aes_crypt != nullptr);
        ssl_symm_crypt_free(aes_crypt);

        // 测试加密 - 无iv
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key), nullptr,
                                       0, 1, &error);
        EXPECT_TRUE(aes_crypt != nullptr);
        ssl_symm_crypt_free(aes_crypt);

        // 测试解密
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 0, &error);
        EXPECT_TRUE(aes_crypt != nullptr);
        ssl_symm_crypt_free(aes_crypt);

        // 测试解密 - 无iv
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key), nullptr,
                                       0, 0, &error);
        EXPECT_TRUE(aes_crypt != nullptr);
        ssl_symm_crypt_free(aes_crypt);
    }

    {
        uint8_t key[31] = {0};
        uint8_t iv[16] = {0};
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        uint64_t error = 0;
        ssl_symm_crypt_t *aes_crypt = NULL;

        for (int i = 0; i < sizeof(key); i++) {
            key[i] = 'a' + i % 26;
        }
        for (int i = 0; i < sizeof(iv); i++) {
            iv[i] = 'a' + i % 26;
        }
        // 测试加密 - 错误 key len
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 1, &error);
        EXPECT_TRUE(aes_crypt == nullptr);
        ssl_symm_crypt_free(aes_crypt);

        // 测试解密 - 错误 key len
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 0, &error);
        EXPECT_TRUE(aes_crypt == nullptr);
        ssl_symm_crypt_free(aes_crypt);
    }

    {
        uint8_t key[32] = {0};
        uint8_t iv[15] = {0};
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        uint64_t error = 0;
        ssl_symm_crypt_t *aes_crypt = NULL;

        for (int i = 0; i < sizeof(key); i++) {
            key[i] = 'a' + i % 26;
        }
        for (int i = 0; i < sizeof(iv); i++) {
            iv[i] = 'a' + i % 26;
        }
        // 测试加密 - 错误 iv len
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 1, &error);
        EXPECT_TRUE(aes_crypt == nullptr);
        ssl_symm_crypt_free(aes_crypt);

        // 测试解密 - 错误 iv len
        aes_crypt = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 0, &error);
        EXPECT_TRUE(aes_crypt == nullptr);
        ssl_symm_crypt_free(aes_crypt);
    }
}

TEST(symm, encrypt_block)
{
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    uint64_t error = 0;
    ssl_symm_crypt_t *aes_crypt_enc = NULL;
    ssl_symm_crypt_t *aes_crypt_dec = NULL;
    for (int i = 0; i < sizeof(key); i++) {
        key[i] = 'a' + i % 26;
    }
    for (int i = 0; i < sizeof(iv); i++) {
        iv[i] = 'a' + i % 26;
    }
    aes_crypt_enc = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 1, &error);
    ASSERT_TRUE(aes_crypt_enc != nullptr);
    aes_crypt_dec = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 0, &error);
    ASSERT_TRUE(aes_crypt_dec != nullptr);

    uint8_t src[59] = {0};
    for (int i = 0; i < sizeof(src); i++) {
        src[i] = '0' + i % 10;
    }
    std::vector<uint8_t> enc;
    std::vector<uint8_t> dec;

    {
        int block_size = ssl_symm_block_size(aes_crypt_enc);
        ASSERT_TRUE(block_size > 0);
        int block_out_size = ssl_symm_block_out_size(aes_crypt_enc);
        ASSERT_TRUE(block_out_size > 0);
        uint8_t *enc_buf = new (std::nothrow) uint8_t[block_out_size];
        ASSERT_TRUE(enc_buf != nullptr);

        int remain = sizeof(src);
        int last = 0;
        while (remain > 0) {
            uint8_t *in = src + sizeof(src) - remain;
            int in_len = remain > block_size ? block_size : remain;
            last = remain == in_len ? 1 : 0;
            int len = ssl_symm_encrypt_block(aes_crypt_enc, in, in_len, last, enc_buf,
                                             block_out_size, &error);
            char errstr[1024] = {0};
            ssl_error_string_n(error, errstr, sizeof(errstr));
            ASSERT_TRUE(len > 0) << "error: " << errstr;
            enc.insert(enc.end(), enc_buf, enc_buf + len);
            remain -= in_len;
        }

        delete[] enc_buf;
    }

    {
        int block_size = ssl_symm_block_size(aes_crypt_dec);
        ASSERT_TRUE(block_size > 0);
        int block_out_size = ssl_symm_block_out_size(aes_crypt_dec);
        ASSERT_TRUE(block_out_size > 0);
        uint8_t *dec_buf = new (std::nothrow) uint8_t[block_out_size];
        ASSERT_TRUE(dec_buf != nullptr);

        int remain = enc.size();
        int last = 0;
        while (remain > 0) {
            uint8_t *in = enc.data() + enc.size() - remain;
            int in_len = remain > block_size ? block_size : remain;
            last = remain == in_len ? 1 : 0;
            int len = ssl_symm_decrypt_block(aes_crypt_dec, in, in_len, last, dec_buf,
                                             block_out_size, &error);
            char errstr[1024] = {0};
            ssl_error_string_n(error, errstr, sizeof(errstr));
            ASSERT_TRUE(len > 0) << "error: " << errstr;
            dec.insert(dec.end(), dec_buf, dec_buf + len);
            remain -= in_len;
        }

        delete[] dec_buf;
    }

    EXPECT_EQ(sizeof(src), dec.size());
    for (int i = 0; i < sizeof(src); i++) {
        EXPECT_EQ(src[i], dec[i]);
    }

    ssl_symm_crypt_free(aes_crypt_dec);
    ssl_symm_crypt_free(aes_crypt_enc);
}

TEST(symm, encrypt)
{
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    uint64_t error = 0;
    ssl_symm_crypt_t *aes_crypt_enc = NULL;
    ssl_symm_crypt_t *aes_crypt_dec = NULL;
    for (int i = 0; i < sizeof(key); i++) {
        key[i] = 'a' + i % 26;
    }
    for (int i = 0; i < sizeof(iv); i++) {
        iv[i] = 'a' + i % 26;
    }
    aes_crypt_enc = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 1, &error);
    ASSERT_TRUE(aes_crypt_enc != nullptr);
    aes_crypt_dec = ssl_symm_crypt_new(cipher, (const uint8_t *)key, sizeof(key),
                                       (const uint8_t *)iv, sizeof(iv), 0, &error);
    ASSERT_TRUE(aes_crypt_dec != nullptr);

    uint8_t src[59] = {0};
    for (int i = 0; i < sizeof(src); i++) {
        src[i] = '0' + i % 10;
    }
    uint8_t *enc = NULL;
    int enc_len = 0;

    enc_len = ssl_symm_encrypt(aes_crypt_enc, src, sizeof(src), &enc, &error);
    ASSERT_TRUE(enc_len > 0);
    ASSERT_TRUE(enc != nullptr);

    uint8_t *dec = NULL;
    int dec_len = 0;
    dec_len = ssl_symm_decrypt(aes_crypt_dec, enc, enc_len, &dec, &error);
    ASSERT_TRUE(dec_len > 0);
    ASSERT_TRUE(dec != nullptr);

    EXPECT_EQ(sizeof(src), dec_len);
    EXPECT_EQ(0, memcmp(src, dec, sizeof(src)));

    ssl_symm_crypt_free(aes_crypt_dec);
    ssl_symm_crypt_free(aes_crypt_enc);
}

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
