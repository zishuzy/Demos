cmake_minimum_required(VERSION 3.12)

project(utils_encoding)

if(NOT DEFINED DEMO_ROOT_PATH)
    set(DEMO_ROOT_PATH ${PROJECT_SOURCE_DIR}/../..)
    message(STATUS "Set DEMO_ROOT_PATH: ${DEMO_ROOT_PATH}")
endif()

include(${DEMO_ROOT_PATH}/cmake/platform_config.cmake)
include_directories(${DEMO_ROOT_PATH})

enable_testing()

find_package(GTest REQUIRED)

link_libraries(GTest::gtest GTest::gmock)

add_executable(test_utils_encoding_base64 test_base64.cpp base64.c)
add_test(NAME utils_encoding_base64 COMMAND test_utils_encoding_base64)
