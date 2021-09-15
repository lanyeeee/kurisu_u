# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.0.0)  
# 项目名称
project(kurisu)

set(CMAKE_BUILD_TYPE "Release")
SET(LIBRARY_OUTPUT_PATH ./build/lib)
set(CMAKE_CXX_FLAGS "-pthread -std=gnu++17 -O3")

#向工程添加多个特定的头文件搜索路径,路径之间用空格分隔
#include_directories(include)

#子目录
add_subdirectory(src)
add_subdirectory(src/fmt)


install(
        TARGETS kurisu
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        )

install(
    DIRECTORY include DESTINATION build/include
    )