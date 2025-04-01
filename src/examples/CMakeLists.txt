cmake_minimum_required(VERSION 3.26)



set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(POSITION_INDEPENDENT_CODE ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")


find_package(OpenSSL 3.1 REQUIRED)
if (OPENSSL_FOUND)
    message(STATUS, "OPENSSL Version -> ${OPENSSL_VERSION}")
    message(STATUS, "OPENSSL INC DiR -> ${OPENSSL_INCLUDE_DIR}")
    message(STATUS, "OPENSSL LIBRARY -> ${OPENSSL_LIBRARIES}")
endif()

link_directories(${CMAKE_BINARY_DIR}/src/BigNumbers
                ${CMAKE_BINARY_DIR}/src/ECPoint
                ${CMAKE_BINARY_DIR}/src/Polynomial
                ${CMAKE_BINARY_DIR}/src/AsymKey
                ${CMAKE_BINARY_DIR}/src/SecretShare
                ${CMAKE_BINARY_DIR}/src/Utils)

add_executable(asym_example asym_execute.cc)
target_include_directories(asym_example PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asym_example pthread OpenSSL::Crypto  -lASymKey -lSecretShare -lPolynomial -lECPoint -lBigNumbers -lUtils)


