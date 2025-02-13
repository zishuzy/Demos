cmake_minimum_required(VERSION 3.12)

project(utils_ssl)

if(NOT DEFINED DEMO_ROOT_PATH)
    set(DEMO_ROOT_PATH ${PROJECT_SOURCE_DIR}/../..)
    message(STATUS "Set DEMO_ROOT_PATH: ${DEMO_ROOT_PATH}")
endif()

include(${DEMO_ROOT_PATH}/cmake/platform_config.cmake)
include_directories(${DEMO_ROOT_PATH})

enable_testing()

find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

link_libraries(
    GTest::gtest
    GTest::gmock
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_executable(test_utils_ssl
    test_ssl.c
    rsa.c
    symm.c
    ssl.c
    ${DEMO_ROOT_PATH}/utils/encoding/base64.c
)

add_executable(test_utils_ssl_symm test_symm.cpp symm.c ssl.c)
add_test(NAME utils_ssl_symm COMMAND test_utils_ssl_symm)

add_executable(test_utils_ssl_rsa test_ssl_rsa.cpp rsa.c ssl.c)
add_test(NAME utils_ssl_rsa COMMAND test_utils_ssl_rsa)
