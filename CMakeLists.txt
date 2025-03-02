cmake_minimum_required(VERSION 3.22)
cmake_policy(VERSION 3.22)

project(tinytransfer)

# message(STATUS "Building tinytransfer")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# made folder structure neat 
set(MODULE_SOURCE "${PROJECT_SOURCE_DIR}/src")
set(SUBMODULES_SOURCE "${PROJECT_SOURCE_DIR}/submodules")

# For pythin bindings
add_subdirectory(${SUBMODULES_SOURCE}/pybind11)

add_library(heatshrink  
    ${SUBMODULES_SOURCE}/heatshrink/heatshrink_encoder.c 
    ${SUBMODULES_SOURCE}/heatshrink/heatshrink_decoder.c
)
target_include_directories(heatshrink PUBLIC ${SUBMODULES_SOURCE}/heatshrink)
target_compile_options(heatshrink PRIVATE -Wno-unknown-pragmas)

add_library(tinytransfer ${MODULE_SOURCE}/tinyTransfer.cpp)
target_include_directories(tinytransfer PUBLIC ${MODULE_SOURCE})
target_link_libraries(tinytransfer PUBLIC heatshrink pybind11::pybind11)

# For pythin bindings
pybind11_add_module(tinytransfer_py ${MODULE_SOURCE}/tinyTransfer.cpp)
target_include_directories(tinytransfer_py PRIVATE ${MODULE_SOURCE})
target_link_libraries(tinytransfer_py PRIVATE tinytransfer)



