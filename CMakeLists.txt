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
    target_compile_options(heatshrink PRIVATE -Wno-unknown-pragmas -Wno-unused-variable -Wno-implicit-fallthrough)
endif()

target_link_libraries(tinytransfer PRIVATE heatshrink)

# Mbed keeps its selected Debug/Develop/Release compiler options on this
# interface target. Every compiled project library must link it directly;
# inheriting tinytransfer at the final executable does not apply the options
# retroactively to tinyTransfer.cpp or the Heatshrink C sources.
if(COMPILE_WITH_MBED_CE)
    target_link_libraries(heatshrink PRIVATE mbed-core-flags)
    target_link_libraries(tinytransfer PRIVATE mbed-core-flags)
endif()
