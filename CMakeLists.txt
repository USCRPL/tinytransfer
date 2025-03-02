cmake_minimum_required(VERSION 3.22)
cmake_policy(VERSION 3.22)

project(tinytransfer)

# message(STATUS "Building tinytransfer")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# # made folder structure neat 
set(MODULE_SOURCE "${PROJECT_SOURCE_DIR}/src")
set(SUBMOBULES_SOURCE "${PROJECT_SOURCE_DIR}/submodules")

add_library(heatshrink STATIC ${SUBMOBULES_SOURCE}/heatshrink/heatshrink_encoder.c ${SUBMOBULES_SOURCE}/heatshrink/heatshrink_decoder.c)
add_library(tinytransfer ${MODULE_SOURCE}/tinytransfer.cpp)

# For pythin bindings --
add_subdirectory(${SUBMOBULES_SOURCE}/pybind11)
pybind11_add_module(cooked ${MODULE_SOURCE}/test.cpp)
# --

target_include_directories(heatshrink PUBLIC ${SUBMOBULES_SOURCE}/heatshrink)
target_include_directories(tinytransfer PUBLIC ${MODULE_SOURCE})

target_compile_options(heatshrink PRIVATE -Wno-unknown-pragmas)

target_link_libraries(tinytransfer heatshrink )
