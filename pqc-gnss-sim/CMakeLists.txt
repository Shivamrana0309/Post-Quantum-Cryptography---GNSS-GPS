cmake_minimum_required(VERSION 3.16)
project(PQC_GNSS_Sim
    VERSION 1.0.0
    DESCRIPTION "Post-Quantum Cryptography GNSS/GPS Simulation"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Common interface library containing shared structs and headers
add_library(pqc_gnss_common INTERFACE)
target_include_directories(pqc_gnss_common INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/common
)

# Satellite Transmitter Executable
add_executable(transmitter transmitter/main.cpp)
target_link_libraries(transmitter PRIVATE pqc_gnss_common)

# Ground Receiver Executable
add_executable(receiver receiver/main.cpp)
target_link_libraries(receiver PRIVATE pqc_gnss_common)
