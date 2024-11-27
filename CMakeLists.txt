cmake_minimum_required(VERSION 3.5)

project(demo_cpp)

include(cmake/platform_config.cmake)

set(DEMO_ROOT_START ON)
set(DEMO_ROOT_PATH ${PROJECT_SOURCE_DIR})
message(STATUS "Set DEMO_ROOT_PATH: ${DEMO_ROOT_PATH}")

include_directories(${PROJECT_SOURCE_DIR})

add_subdirectory(utils)
add_subdirectory(x11_win_monitor)
