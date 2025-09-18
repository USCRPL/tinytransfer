cmake_minimum_required(VERSION 3.22)
cmake_policy(VERSION 3.22)

project(tinytransfer)

message(STATUS "Building tinytransfer")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

add_compile_definitions(HEATSHRINK_DYNAMIC_ALLOC=0)

add_library(heatshrink ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink/heatshrink_encoder.c ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink/heatshrink_decoder.c)
add_library(tinytransfer ${CMAKE_CURRENT_SOURCE_DIR}/tinyTransfer.cpp)

target_include_directories(heatshrink PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink)
target_include_directories(tinytransfer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT TINYTRANSFER_X86)
    target_compile_options(heatshrink PRIVATE -Wno-unknown-pragmas)
endif()

target_link_libraries(tinytransfer heatshrink)
