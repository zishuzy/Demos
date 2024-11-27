cmake_minimum_required(VERSION 3.5)

project(utils_x11)

set(DEMO_ROOT_PATH ${PROJECT_SOURCE_DIR}/../..)

include(${DEMO_ROOT_PATH}/cmake/platform_config.cmake)

find_package(X11 REQUIRED)

add_library(utils_x11 OBJECT utils_x11.cpp)
target_link_libraries(utils_x11 PUBLIC X11::X11 X11::XRes)
