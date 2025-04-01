cmake_minimum_required(VERSION 3.26)

project(nakasendo_sdk LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(POSITION_INDEPENDENT_CODE ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
add_compile_options(-fPIC)

# Find Python
find_package(Python REQUIRED COMPONENTS Development Interpreter)

find_package(OpenSSL 3.1 REQUIRED)
if (OPENSSL_FOUND)
    message(STATUS, "OPENSSL Version -> ${OPENSSL_VERSION}")
    message(STATUS, "OPENSSL INC DiR -> ${OPENSSL_INCLUDE_DIR}")
    message(STATUS, "OPENSSL LIBRARY -> ${OPENSSL_LIBRARIES}")
endif()

# find pybind11
find_package(pybind11 REQUIRED)

# include the TOML settings
# Add toml11 as an external library
add_subdirectory(src/tools/toml11)

# Include toml11 headers
include_directories(src/tools/toml11)
# Enable testing
enable_testing()

include_directories(${CMAKE_SOURCE_DIR}/src)
add_subdirectory(src/BigNumbers)
add_subdirectory(src/ECPoint) 
add_subdirectory(src/Polynomial)
add_subdirectory(src/AsymKey)
add_subdirectory(src/Utils)
add_subdirectory(src/SecretShare)
add_subdirectory(src/python_bindings)
add_subdirectory(src/tests)

add_subdirectory(src/examples)


