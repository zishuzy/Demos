#include "base64.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base64.h"

TEST(base64, encode_decode)
{
    std::vector<std::pair<std::string, std::string>> vec_case_1 = {
        {"1", "MQ=="},
        {"2", "Mg=="},
        {"12", "MTI="},
        {"123", "MTIz"},
        {"1234", "MTIzNA=="},
        {"12345", "MTIzNDU="},
        {"123456", "MTIzNDU2"},
        {"1234567", "MTIzNDU2Nw=="},
        {"`1234567890-=~!@#$%^&*()_+qwertyuiop[]\\{}|asdfghjkl;':\"zxcvbnm,./<>?",
         "YDEyMzQ1Njc4OTAtPX4hQCMkJV4mKigpXytxd2VydHl1aW9wW11ce318YXNkZmdoamtsOyc6Inp4Y3Z"
         "ibm0sLi88Pj8="},
        {"U7QhaeuDIAcMOzEMbmmG09pu0q0jyDQb0xmzn6gaUICOaJIRTI5TTo8vTiSfXZiLJAt3Xl010T7s4TE"
         "quBHhl3C5XEx26Tu7ijHQhKkEABdOTpaJ5qxO1OumnGKef7EQTvvO6W7XKeH6rs0CNRG3XdnN9zFGJa"
         "eocWw6MzD7JvwMalNVwzGa5fgnx1zLOJotmCraZrcpG3DLaeOCnRrmji0iMu1thBjMeIWMedZ1ToBPZ"
         "XbQJVa8dz7Lakg7TmjH18yHaz17mXe00taTVZhUR7Ovv7FHHlULcQjOyudCq5a83QecKsFSj1s47OXz"
         "o5wFKJTorxpaXTLMfBSlqaVZd3Hdxg7Twexx6oqTaObjg1f6TlkAYbddSmJHFNxrECNgfvGT888Mb9V"
         "SbJMCKQE2DTdAgn63xvkCA2gLaqjZx76mHq7SLttZ4jG3q9tOuAUjvrNCUxicTEBQZpxhjnJW3j9HnA"
         "yWg7y7mxPL04OHHvXz7k4VtcmDQQpqWW9Ji6CNBRl1a1W3Wn1A94lFQdmSb4ANn6hKm9H89ItC4KZzx"
         "C3q4syzFBsY8cwoMIiKkc2ShGxhP507qrBaUWhogkL9vUbj1wBioEVJJ32eidgyvgrnTcgq9fvwjk5W"
         "OnfQ2otuYd2ngZU6EUQRlzfnWyO49PkVhUadOoX1Us9OoZrWXV1hZBD4yrxrBN5QcGcFPwRZnPhJppi"
         "nU3FKEH88XT37EzZ4GtZ0ceqp96BOMfHmkPhTibbUCeA4RgenCLtPrwNThy2QzOkBzlya7HztSK2iKA"
         "GBuXkPgbWKLqChPCsUBihUWXZMnpgQoDkVXt3VoTIa61JO5pcch8j2VG7p4mw29P9eoP2tGzttbXi7U"
         "55Ka7MDqO1dLyK7YFTVh56Fl5WTDnQ3GEAzo5wwFIa4gkpC7HUizXD89tSHEeRus7743AJMzJACiIj7"
         "UUmlxLkK5KoJUF1zkt1ewMLN1vtrBupL2rHNk2JhKmLEfqvlinNVJ4LF6plZURhtgQZKNmMwOjCXp",
         "VTdRaGFldURJQWNNT3pFTWJtbUcwOXB1MHEwanlEUWIweG16bjZnYVVJQ09hSklSVEk1VFRvOHZUaVN"
         "mWFppTEpBdDNYbDAxMFQ3czRURXF1QkhobDNDNVhFeDI2VHU3aWpIUWhLa0VBQmRPVHBhSjVxeE8xT3"
         "VtbkdLZWY3RVFUdnZPNlc3WEtlSDZyczBDTlJHM1hkbk45ekZHSmFlb2NXdzZNekQ3SnZ3TWFsTlZ3e"
         "kdhNWZnbngxekxPSm90bUNyYVpyY3BHM0RMYWVPQ25Scm1qaTBpTXUxdGhCak1lSVdNZWRaMVRvQlBa"
         "WGJRSlZhOGR6N0xha2c3VG1qSDE4eUhhejE3bVhlMDB0YVRWWmhVUjdPdnY3RkhIbFVMY1FqT3l1ZEN"
         "xNWE4M1FlY0tzRlNqMXM0N09Yem81d0ZLSlRvcnhwYVhUTE1mQlNscWFWWmQzSGR4ZzdUd2V4eDZvcV"
         "RhT2JqZzFmNlRsa0FZYmRkU21KSEZOeHJFQ05nZnZHVDg4OE1iOVZTYkpNQ0tRRTJEVGRBZ242M3h2a"
         "0NBMmdMYXFqWng3Nm1IcTdTTHR0WjRqRzNxOXRPdUFVanZyTkNVeGljVEVCUVpweGhqbkpXM2o5SG5B"
         "eVdnN3k3bXhQTDA0T0hIdlh6N2s0VnRjbURRUXBxV1c5Smk2Q05CUmwxYTFXM1duMUE5NGxGUWRtU2I"
         "0QU5uNmhLbTlIODlJdEM0S1p6eEMzcTRzeXpGQnNZOGN3b01JaUtrYzJTaEd4aFA1MDdxckJhVVdob2"
         "drTDl2VWJqMXdCaW9FVkpKMzJlaWRneXZncm5UY2dxOWZ2d2prNVdPbmZRMm90dVlkMm5nWlU2RVVRU"
         "mx6Zm5XeU80OVBrVmhVYWRPb1gxVXM5T29acldYVjFoWkJENHlyeHJCTjVRY0djRlB3UlpuUGhKcHBp"
         "blUzRktFSDg4WFQzN0V6WjRHdFowY2VxcDk2Qk9NZkhta1BoVGliYlVDZUE0UmdlbkNMdFByd05UaHk"
         "yUXpPa0J6bHlhN0h6dFNLMmlLQUdCdVhrUGdiV0tMcUNoUENzVUJpaFVXWFpNbnBnUW9Ea1ZYdDNWb1"
         "RJYTYxSk81cGNjaDhqMlZHN3A0bXcyOVA5ZW9QMnRHenR0YlhpN1U1NUthN01EcU8xZEx5SzdZRlRWa"
         "DU2Rmw1V1REblEzR0VBem81d3dGSWE0Z2twQzdIVWl6WEQ4OXRTSEVlUnVzNzc0M0FKTXpKQUNpSWo3"
         "VVVtbHhMa0s1S29KVUYxemt0MWV3TUxOMXZ0ckJ1cEwyckhOazJKaEttTEVmcXZsaW5OVko0TEY2cGx"
         "aVVJodGdRWktObU13T2pDWHA="},
    };

    for (const auto kv : vec_case_1) {
        char *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_encode((uint8_t *)kv.first.c_str(), kv.first.size(), &dst, &dst_len);
        EXPECT_EQ(ret, 0);
        std::string str_out(dst, dst_len);
        EXPECT_EQ(dst, kv.second);
        free(dst);
    }

    for (const auto kv : vec_case_1) {
        uint8_t *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_decode(kv.second.c_str(), kv.second.size(), &dst, &dst_len);
        EXPECT_EQ(ret, 0);
        std::string str_out((char *)dst, dst_len);
        EXPECT_EQ(str_out, kv.first);
        free(dst);
    }

    std::vector<std::pair<std::vector<uint8_t>, std::string>> vec_case_2 = {
        {{1}, "AQ=="},
        {{2}, "Ag=="},
        {{1, 2}, "AQI="},
        {{1, 2, 3}, "AQID"},
        {{1, 2, 3, 4}, "AQIDBA=="},
        {{1, 2, 3, 4, 5}, "AQIDBAU="},
        {{1, 2, 3, 4, 5, 6}, "AQIDBAUG"},
        {{1, 2, 3, 4, 5, 6, 7}, "AQIDBAUGBw=="},
    };

    for (const auto kv : vec_case_2) {
        char *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_encode((uint8_t *)kv.first.data(), kv.first.size(), &dst, &dst_len);
        EXPECT_EQ(ret, 0);
        std::string str_out(dst, dst_len);
        EXPECT_EQ(dst, kv.second);
        free(dst);
    }

    for (const auto kv : vec_case_2) {
        uint8_t *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_decode(kv.second.c_str(), kv.second.size(), &dst, &dst_len);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(dst_len, kv.first.size());
        EXPECT_EQ(memcmp(dst, kv.first.data(), dst_len), 0);
        free(dst);
    }
}

TEST(base64, url_encode_decode)
{
    std::vector<std::pair<std::string, std::string>> vec_case_1 = {
        {"1", "MQ"},
        {"2", "Mg"},
        {"12", "MTI"},
        {"123", "MTIz"},
        {"1234", "MTIzNA"},
        {"12345", "MTIzNDU"},
        {"123456", "MTIzNDU2"},
        {"1234567", "MTIzNDU2Nw"},
        {"`1234567890-=~!@#$%^&*()_+qwertyuiop[]\\{}|asdfghjkl;':\"zxcvbnm,./<>?",
         "YDEyMzQ1Njc4OTAtPX4hQCMkJV4mKigpXytxd2VydHl1aW9wW11ce318YXNkZmdoamtsOyc6Inp4Y3Z"
         "ibm0sLi88Pj8"},
        {"U7QhaeuDIAcMOzEMbmmG09pu0q0jyDQb0xmzn6gaUICOaJIRTI5TTo8vTiSfXZiLJAt3Xl010T7s4TE"
         "quBHhl3C5XEx26Tu7ijHQhKkEABdOTpaJ5qxO1OumnGKef7EQTvvO6W7XKeH6rs0CNRG3XdnN9zFGJa"
         "eocWw6MzD7JvwMalNVwzGa5fgnx1zLOJotmCraZrcpG3DLaeOCnRrmji0iMu1thBjMeIWMedZ1ToBPZ"
         "XbQJVa8dz7Lakg7TmjH18yHaz17mXe00taTVZhUR7Ovv7FHHlULcQjOyudCq5a83QecKsFSj1s47OXz"
         "o5wFKJTorxpaXTLMfBSlqaVZd3Hdxg7Twexx6oqTaObjg1f6TlkAYbddSmJHFNxrECNgfvGT888Mb9V"
         "SbJMCKQE2DTdAgn63xvkCA2gLaqjZx76mHq7SLttZ4jG3q9tOuAUjvrNCUxicTEBQZpxhjnJW3j9HnA"
         "yWg7y7mxPL04OHHvXz7k4VtcmDQQpqWW9Ji6CNBRl1a1W3Wn1A94lFQdmSb4ANn6hKm9H89ItC4KZzx"
         "C3q4syzFBsY8cwoMIiKkc2ShGxhP507qrBaUWhogkL9vUbj1wBioEVJJ32eidgyvgrnTcgq9fvwjk5W"
         "OnfQ2otuYd2ngZU6EUQRlzfnWyO49PkVhUadOoX1Us9OoZrWXV1hZBD4yrxrBN5QcGcFPwRZnPhJppi"
         "nU3FKEH88XT37EzZ4GtZ0ceqp96BOMfHmkPhTibbUCeA4RgenCLtPrwNThy2QzOkBzlya7HztSK2iKA"
         "GBuXkPgbWKLqChPCsUBihUWXZMnpgQoDkVXt3VoTIa61JO5pcch8j2VG7p4mw29P9eoP2tGzttbXi7U"
         "55Ka7MDqO1dLyK7YFTVh56Fl5WTDnQ3GEAzo5wwFIa4gkpC7HUizXD89tSHEeRus7743AJMzJACiIj7"
         "UUmlxLkK5KoJUF1zkt1ewMLN1vtrBupL2rHNk2JhKmLEfqvlinNVJ4LF6plZURhtgQZKNmMwOjCXp",
         "VTdRaGFldURJQWNNT3pFTWJtbUcwOXB1MHEwanlEUWIweG16bjZnYVVJQ09hSklSVEk1VFRvOHZUaVN"
         "mWFppTEpBdDNYbDAxMFQ3czRURXF1QkhobDNDNVhFeDI2VHU3aWpIUWhLa0VBQmRPVHBhSjVxeE8xT3"
         "VtbkdLZWY3RVFUdnZPNlc3WEtlSDZyczBDTlJHM1hkbk45ekZHSmFlb2NXdzZNekQ3SnZ3TWFsTlZ3e"
         "kdhNWZnbngxekxPSm90bUNyYVpyY3BHM0RMYWVPQ25Scm1qaTBpTXUxdGhCak1lSVdNZWRaMVRvQlBa"
         "WGJRSlZhOGR6N0xha2c3VG1qSDE4eUhhejE3bVhlMDB0YVRWWmhVUjdPdnY3RkhIbFVMY1FqT3l1ZEN"
         "xNWE4M1FlY0tzRlNqMXM0N09Yem81d0ZLSlRvcnhwYVhUTE1mQlNscWFWWmQzSGR4ZzdUd2V4eDZvcV"
         "RhT2JqZzFmNlRsa0FZYmRkU21KSEZOeHJFQ05nZnZHVDg4OE1iOVZTYkpNQ0tRRTJEVGRBZ242M3h2a"
         "0NBMmdMYXFqWng3Nm1IcTdTTHR0WjRqRzNxOXRPdUFVanZyTkNVeGljVEVCUVpweGhqbkpXM2o5SG5B"
         "eVdnN3k3bXhQTDA0T0hIdlh6N2s0VnRjbURRUXBxV1c5Smk2Q05CUmwxYTFXM1duMUE5NGxGUWRtU2I"
         "0QU5uNmhLbTlIODlJdEM0S1p6eEMzcTRzeXpGQnNZOGN3b01JaUtrYzJTaEd4aFA1MDdxckJhVVdob2"
         "drTDl2VWJqMXdCaW9FVkpKMzJlaWRneXZncm5UY2dxOWZ2d2prNVdPbmZRMm90dVlkMm5nWlU2RVVRU"
         "mx6Zm5XeU80OVBrVmhVYWRPb1gxVXM5T29acldYVjFoWkJENHlyeHJCTjVRY0djRlB3UlpuUGhKcHBp"
         "blUzRktFSDg4WFQzN0V6WjRHdFowY2VxcDk2Qk9NZkhta1BoVGliYlVDZUE0UmdlbkNMdFByd05UaHk"
         "yUXpPa0J6bHlhN0h6dFNLMmlLQUdCdVhrUGdiV0tMcUNoUENzVUJpaFVXWFpNbnBnUW9Ea1ZYdDNWb1"
         "RJYTYxSk81cGNjaDhqMlZHN3A0bXcyOVA5ZW9QMnRHenR0YlhpN1U1NUthN01EcU8xZEx5SzdZRlRWa"
         "DU2Rmw1V1REblEzR0VBem81d3dGSWE0Z2twQzdIVWl6WEQ4OXRTSEVlUnVzNzc0M0FKTXpKQUNpSWo3"
         "VVVtbHhMa0s1S29KVUYxemt0MWV3TUxOMXZ0ckJ1cEwyckhOazJKaEttTEVmcXZsaW5OVko0TEY2cGx"
         "aVVJodGdRWktObU13T2pDWHA"},
    };

    for (const auto kv : vec_case_1) {
        char *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_encode_url((uint8_t *)kv.first.c_str(), kv.first.size(), &dst,
                                &dst_len);
        EXPECT_EQ(ret, 0);
        std::string str_out(dst, dst_len);
        EXPECT_EQ(dst, kv.second);
        free(dst);
    }

    for (const auto kv : vec_case_1) {
        uint8_t *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_decode_url(kv.second.c_str(), kv.second.size(), &dst, &dst_len);
        EXPECT_EQ(ret, 0);
        std::string str_out((char *)dst, dst_len);
        EXPECT_EQ(str_out, kv.first);
        free(dst);
    }

    std::vector<std::pair<std::vector<uint8_t>, std::string>> vec_case_2 = {
        {{1}, "AQ"},
        {{2}, "Ag"},
        {{1, 2}, "AQI"},
        {{1, 2, 3}, "AQID"},
        {{1, 2, 3, 4}, "AQIDBA"},
        {{1, 2, 3, 4, 5}, "AQIDBAU"},
        {{1, 2, 3, 4, 5, 6}, "AQIDBAUG"},
        {{1, 2, 3, 4, 5, 6, 7}, "AQIDBAUGBw"},
    };

    for (const auto kv : vec_case_2) {
        char *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_encode_url((uint8_t *)kv.first.data(), kv.first.size(), &dst,
                                &dst_len);
        EXPECT_EQ(ret, 0);
        std::string str_out(dst, dst_len);
        EXPECT_EQ(dst, kv.second);
        free(dst);
    }

    for (const auto kv : vec_case_2) {
        uint8_t *dst = NULL;
        size_t dst_len = 0;
        int ret = 0;
        ret = base64_decode_url(kv.second.c_str(), kv.second.size(), &dst, &dst_len);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(dst_len, kv.first.size());
        EXPECT_EQ(memcmp(dst, kv.first.data(), dst_len), 0);
        free(dst);
    }
}

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
