#include "ssl.h"
#include "symm.h"
#include "rsa.h"
#include "utils/encoding/base64.h"

#include "utils/log/log.h"

static char g_err_str[4096] = {0};

char *get_error_str(uint64_t error)
{
    memset(g_err_str, 0, sizeof(g_err_str));
    ssl_error_string_n(error, g_err_str, sizeof(g_err_str));
    return g_err_str;
}

int test_rsa(void)
{
    int res = 0;
    uint64_t error = 0;

    {
        EVP_PKEY *evp_pkey = NULL;
        res = rsa_generate_pkey(2048, &evp_pkey, &error);
        if (res != 0) {
            LOG_ERROR("Failed to generate pkey: %s", get_error_str(error));
            return -1;
        }

        res = rsa_pub_key_to_file(evp_pkey, "pub_key.pem", &error);
        if (res != 0) {
            LOG_ERROR("Failed to save pub key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Save pub_key to file success");

        res = rsa_pri_key_to_file(evp_pkey, "pri_key.pem", &error);
        if (res != 0) {
            LOG_ERROR("Failed to save pub key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Save pri_key to file success");

        rsa_free_pkey(evp_pkey);
        evp_pkey = NULL;
    }

    {
        EVP_PKEY *pub_key = NULL;
        EVP_PKEY *pri_key = NULL;
        res = rsa_load_pub_key_from_file("pub_key.pem", &pub_key, &error);
        if (res != 0) {
            LOG_ERROR("Failed to load pub key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Load pub_key from file success");

        res = rsa_load_pri_key_from_file("pri_key.pem", &pub_key, &error);
        if (res != 0) {
            LOG_ERROR("Failed to load pri key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Load pri_key from file success");

        rsa_free_pkey(pub_key);
        rsa_free_pkey(pri_key);
    }

    {
        EVP_PKEY *pub_key = NULL;
        EVP_PKEY *pub_key_2 = NULL;
        char *pub_key_base64 = NULL;
        char *pub_key_2_base64 = NULL;
        res = rsa_load_pub_key_from_file("pub_key.pem", &pub_key, &error);
        if (res != 0) {
            LOG_ERROR("Failed to load pub key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Load pub_key from file success");

        res = rsa_pub_key_to_base64(pub_key, &pub_key_base64, &error);
        if (res != 0) {
            LOG_ERROR("Failed to convert pub_key to base64: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Got pub_key base64: %s", pub_key_base64);

        res = rsa_base64_to_pub_key(pub_key_base64, &pub_key_2, &error);
        if (res != 0) {
            LOG_ERROR("Failed to convert base64 to pub_key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Save base64 to file success");

        res = rsa_pub_key_to_base64(pub_key_2, &pub_key_2_base64, &error);
        if (res != 0) {
            LOG_ERROR("Failed to convert pub_key to base64!");
            return -1;
        }
        LOG_INFO("Got pub_key_2 base64: %s", pub_key_2_base64);
        if (strcmp(pub_key_base64, pub_key_2_base64) != 0) {
            LOG_ERROR("Two pub_key is not equal!");
            return -1;
        }

        rsa_free_pkey(pub_key);
        rsa_free_pkey(pub_key_2);
        free(pub_key_base64);
        free(pub_key_2_base64);
    }

    {
        EVP_PKEY *pub_key = NULL;

        res = rsa_load_pub_key_from_file("pub_key.pem", &pub_key, &error);
        if (res != 0) {
            LOG_ERROR("Failed to load pub key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Load pub_key from file success");

        uint8_t *encrypted = NULL;
        size_t encrypted_len = 0;
        char *data = malloc(490);

        for (int i = 0; i < 490; i++) {
            data[i] = 'a' + i % 26;
        }
        LOG_INFO("data[%ld]: %s\n", strlen(data), data);

        res = rsa_encrypt_large(pub_key, (uint8_t *)data, strlen(data), 0, &encrypted,
                                &encrypted_len, &error);
        if (res != 0) {
            LOG_ERROR("Failed to encrypt data: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Got encrypted data len: %ld", encrypted_len);

        char *encrypted_base64 = NULL;
        size_t encrypted_base64_len = 0;
        res = base64_encode(encrypted, encrypted_len, &encrypted_base64,
                            &encrypted_base64_len);
        LOG_INFO("Got encrypted data base64: %s", encrypted_base64);

        EVP_PKEY *pri_key = NULL;
        res = rsa_load_pri_key_from_file("pri_key.pem", &pri_key, &error);
        if (res != 0) {
            LOG_ERROR("Failed to load pri key: %s", get_error_str(error));
            return -1;
        }
        LOG_INFO("Load pri_key from file success");

        uint8_t *decrypted = NULL;
        size_t decrypted_len = 0;
        res = rsa_decrypt_large(pri_key, (uint8_t *)encrypted, encrypted_len, 0,
                                &decrypted, &decrypted_len, &error);
        if (res != 0) {
            LOG_ERROR("Failed to decrypt data: %s", get_error_str(error));
            return -1;
        }

        LOG_INFO("Got decrypted data: %s", (char *)decrypted);

        free(encrypted);
        free(decrypted);
        rsa_free_pkey(pub_key);
        rsa_free_pkey(pri_key);
    }

    LOG_INFO("end!");
    return 0;
}

int test_aes(void)
{
    int res = 0;
    uint64_t error = 0;
    // 示例密钥和IV
    unsigned char key[32] = "0123456789abcdef0123456789abcdef"; // 256位密钥
    unsigned char iv[16] = "0123456789abcdef";                  // 128位IV
    const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();

    // 明文
    uint8_t plaintext[1024] = {0};
    size_t plaintext_len = 159;

    int i = 0;

    for (i = 0; i < plaintext_len; i++) {
        plaintext[i] = 'a' + i % 26;
    }

    printf("      Src text [%ld]: %s\n", strlen((char *)plaintext), plaintext);
    {
        ssl_symm_crypt_t *aes_crypt = NULL;
        aes_crypt =
            ssl_symm_crypt_new(cipher_type, key, sizeof(key), iv, sizeof(iv), 1, &error);
        if (aes_crypt == NULL) {
            LOG_ERROR("Failed to init aes crypt: %s", get_error_str(error));
            return -1;
        }
        int block_size = ssl_symm_block_size(aes_crypt);
        int block_enc_size = ssl_symm_block_out_size(aes_crypt);
        int ciphertext_len = plaintext_len + block_size;
        uint8_t *ciphertext = calloc(1, ciphertext_len);
        if (ciphertext == NULL) {
            LOG_ERROR("Failed to malloc ciphertext");
            return -1;
        }
        uint8_t *buff = calloc(1, block_enc_size);
        if (buff == NULL) {
            LOG_ERROR("Failed to malloc buff");
            return -1;
        }
        int encrypted_len = 0;
        int offset = 0;
        int out_len = 0;
        int last = 0;

        do {
            int remain_len = plaintext_len - offset;
            int in_len = 0;
            int out_len = 0;
            if (remain_len > block_size) {
                in_len = block_size;
                last = 0;
            } else {
                in_len = remain_len;
                last = 1;
            }
            out_len = ssl_symm_encrypt_block(aes_crypt, plaintext + offset, in_len, last,
                                             buff, block_enc_size, &error);
            if (out_len <= 0) {
                LOG_ERROR("Failed to encrypt data: %s", get_error_str(error));
                return -1;
            }
            memcpy(ciphertext + encrypted_len, buff, out_len);
            encrypted_len += out_len;
            offset += in_len;
        } while (last == 0);

        ssl_symm_crypt_free(aes_crypt);

        printf(" Ciphertext is [%d]: ", encrypted_len);
        for (int i = 0; i < encrypted_len; i++) {
            printf("%02x ", ciphertext[i]);
        }
        printf("\n");

        aes_crypt =
            ssl_symm_crypt_new(cipher_type, key, sizeof(key), iv, sizeof(iv), 0, &error);
        if (aes_crypt == NULL) {
            LOG_ERROR("Failed to init aes crypt: %s", get_error_str(error));
            return -1;
        }

        uint8_t *decryptedtext = calloc(1, encrypted_len + 1);
        if (decryptedtext == NULL) {
            LOG_ERROR("Failed to malloc decryptedtext");
            return -1;
        }
        int decrypted_len = 0;
        block_size = ssl_symm_block_size(aes_crypt);
        offset = 0;
        out_len = 0;
        last = 0;

        do {
            int remain_len = encrypted_len - offset;
            int in_len = 0;
            int out_len = 0;
            if (remain_len > block_size) {
                in_len = block_size;
                last = 0;
            } else {
                in_len = remain_len;
                last = 1;
            }
            printf("offset: %d, in_len: %d, last: %d\n", offset, in_len, last);
            out_len = ssl_symm_decrypt_block(aes_crypt, ciphertext + offset, in_len, last,
                                             decryptedtext + decrypted_len,
                                             encrypted_len - decrypted_len, &error);
            if (out_len <= 0) {
                LOG_ERROR("Failed to decrypt data: %s", get_error_str(error));
                return -1;
            }
            decrypted_len += out_len;
            offset += in_len;
        } while (last == 0);

        printf("Decrypted text [%d]: %s\n", decrypted_len, decryptedtext);

        free(ciphertext);
        free(decryptedtext);
        free(buff);
        ssl_symm_crypt_free(aes_crypt);
    }

    {
        uint8_t *ciphertext = NULL;
        int encrypted_len = 0;

        encrypted_len = ssl_symm_encrypt2(cipher_type, key, sizeof(key), iv, sizeof(iv),
                                          plaintext, plaintext_len, &ciphertext, &error);
        if (encrypted_len <= 0) {
            LOG_ERROR("Failed to encrypt data: %s", get_error_str(error));
            return -1;
        }

        printf(" Ciphertext is [%d]: ", encrypted_len);
        for (int i = 0; i < encrypted_len; i++) {
            printf("%02x ", ciphertext[i]);
        }
        printf("\n");

        uint8_t *decryptedtext = NULL;
        int decrypted_len = 0;
        decrypted_len =
            ssl_symm_decrypt2(cipher_type, key, sizeof(key), iv, sizeof(iv), ciphertext,
                              encrypted_len, &decryptedtext, &error);
        if (decrypted_len <= 0) {
            LOG_ERROR("Failed to decrypt data: %s", get_error_str(error));
            return -1;
        }
        printf("Decrypted text [%d]: %s\n", decrypted_len, decryptedtext);

        free(ciphertext);
        free(decryptedtext);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // test_rsa();
    test_aes();
    // test_aes();

    return 0;
}