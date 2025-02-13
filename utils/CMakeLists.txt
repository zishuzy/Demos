cmake_minimum_required(VERSION 3.12)

project(utils)

if(NOT DEFINED DEMO_ROOT_PATH)
    set(DEMO_ROOT_PATH ${PROJECT_SOURCE_DIR}/..)
    message(STATUS "Set DEMO_ROOT_PATH: ${DEMO_ROOT_PATH}")
endif()

include(${DEMO_ROOT_PATH}/cmake/platform_config.cmake)

include_directories(${DEMO_ROOT_PATH})

add_subdirectory(x11)
add_subdirectory(encoding)
add_subdirectory(ssl)
