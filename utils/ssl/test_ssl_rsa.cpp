#include "symm.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

TEST(aes, aes_encrypt)
{
    // // 示例密钥和IV
    // unsigned char key[32] = "0123456789abcdef0123456789abcdef"; // 256位密钥
    // unsigned char iv[16] = "0123456789abcdef";                  // 128位IV

    // // 明文
    // unsigned char *plaintext = (unsigned char *)"Hello, World!";
    // uint8_t *ciphertext = NULL;
    // uint8_t *decryptedtext;
    // size_t decryptedtext_len, ciphertext_len;

    // printf("Src text is: %s\n", plaintext);

    // // 加密
    // aes_encrypt(plaintext, strlen((char *)plaintext), EVP_aes_256_cbc(), key, iv,
    //             &ciphertext, &ciphertext_len, rsa_print_errors, NULL);

    // // 解密
    // aes_decrypt(ciphertext, ciphertext_len, EVP_aes_256_cbc(), key, iv, &decryptedtext,
    //             &decryptedtext_len, rsa_print_errors, NULL);
    // decryptedtext[decryptedtext_len] = '\0'; // 添加字符串结束符

    // // 输出结果
    // printf("Ciphertext is: ");
    // for (int i = 0; i < ciphertext_len; i++) {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\nDecrypted text is: %s\n", decryptedtext);

    // free(ciphertext);
    // free(decryptedtext);

    // return 0;

    // for (const auto kv : vec_case_2) {
    //     uint8_t *dst = NULL;
    //     size_t dst_len = 0;
    //     int ret = 0;
    //     ret = base64_decode(kv.second.c_str(), kv.second.size(), &dst, &dst_len);
    //     EXPECT_EQ(ret, 0);
    //     EXPECT_EQ(dst_len, kv.first.size());
    //     EXPECT_EQ(memcmp(dst, kv.first.data(), dst_len), 0);
    //     free(dst);
    // }
}

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
