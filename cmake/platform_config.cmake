# 检查是否已经包含过该文件
if(NOT DEFINED DEMO_PLATFORM_CONFIG_EXECUTED)
    # 在这里执行配置操作
    message(STATUS "Executing platform_config.cmake")

    # 设置一个变量标记这个文件已经执行过
    set(DEMO_PLATFORM_CONFIG_EXECUTED TRUE CACHE INTERNAL "Indicates that platform_config.cmake has been executed")

    # 生成 compile_commands.json 文件
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

    # 设置 C 标准
    if(NOT DEFINED CMAKE_C_STANDARD)
        set(CMAKE_C_STANDARD 11)
        set(CMAKE_C_STANDARD_REQUIRED ON)
        message(STATUS "Set CMAKE_C_STANDARD as 11")
    endif()

    # 设置 C++ 标准
    if(NOT DEFINED CMAKE_CXX_STANDARD)
        set(CMAKE_CXX_STANDARD 20)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        message(STATUS "Set CMAKE_CXX_STANDARD as 20")
    endif()

    # 设置构建类型
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
        message(STATUS "CMAKE_BUILD_TYPE is not set. Defaulting to Debug.")
    endif()

    # 判断平台并配置编译器
    IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
        message(STATUS "current platform: Linux ")
    ELSEIF(CMAKE_SYSTEM_NAME MATCHES "Windows")
        message(STATUS "current platform: Windows")
    ELSEIF(CMAKE_SYSTEM_NAME MATCHES "Darwin")
        message(STATUS "current platform: Mac os x")
        find_program(LLVM_CLANG clang HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin)
        find_program(LLVM_CLANGPP clang++ HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin)

        if(LLVM_CLANG AND LLVM_CLANGPP)
            SET(CMAKE_C_COMPILER ${LLVM_CLANG})
            SET(CMAKE_CXX_COMPILER ${LLVM_CLANGPP})
        else()
            message(WARNING "LLVM compiler not found, using default compiler")
        endif()
    ELSE()
        message(STATUS "other platform: ${CMAKE_SYSTEM_NAME}")
    ENDIF(CMAKE_SYSTEM_NAME MATCHES "Linux")
else()
    message(STATUS "platform_config.cmake has already been executed, skipping.")
endif()
