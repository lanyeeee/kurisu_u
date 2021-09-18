# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.0.0)  
# 项目名称
project(kurisu)

set(CMAKE_BUILD_TYPE "Release")
set(LIBRARY_OUTPUT_PATH .)
set(CMAKE_CXX_FLAGS "-pthread -std=gnu++17 -O3")


aux_source_directory(src SRCKURISU)
aux_source_directory(src/fmt SRCFMT)

add_library(kurisu STATIC ${SRCKURISU} ${SRCFMT})

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/kurisu)


# #子目录
# add_subdirectory(src)
# add_subdirectory(src/fmt)



install(
        TARGETS kurisu
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        )

install(
    DIRECTORY include/ DESTINATION include
    )
