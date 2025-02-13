cmake_minimum_required(VERSION 3.12)

project(x11_win_monitor)

if(NOT DEFINED DEMO_ROOT_PATH)
    set(DEMO_ROOT_PATH ${PROJECT_SOURCE_DIR}/..)
    message(STATUS "Set DEMO_ROOT_PATH: ${DEMO_ROOT_PATH}")
endif()

include_directories(
    ${DEMO_ROOT_PATH}
)

find_package(X11 REQUIRED)

add_executable(
    x11_win_monitor
    main.cpp
    win_monitor.cpp
)

target_sources(
    x11_win_monitor
    PRIVATE
    ${DEMO_ROOT_PATH}/utils/x11/utils_x11.cpp
)

target_link_libraries(
    x11_win_monitor
    PRIVATE
    X11::X11
    X11::XRes
)
