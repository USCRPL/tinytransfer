cmake_minimum_required(VERSION 3.22)
cmake_policy(VERSION 3.22)

message(STATUS "Building tinytransfer")

add_library(tinytransfer ${CMAKE_CURRENT_SOURCE_DIR}/tinytransfer.cpp ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink/heatshrink_decoder.h ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink/heatshrink_encoder.h ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink/heatshrink_decoder.c ${CMAKE_CURRENT_SOURCE_DIR}/heatshrink/heatshrink_encoder.c)

target_include_directories(tinytransfer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

