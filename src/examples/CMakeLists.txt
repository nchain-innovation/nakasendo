cmake_minimum_required(VERSION 3.26)



set(CMAKE_CXX_STANDARD 17)
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


set(BIGNUMBERS_LIB ${CMAKE_BINARY_DIR}/src/BigNumbers/libBigNumbers.a)
set(ECPOINT_LIB ${CMAKE_BINARY_DIR}/src/ECPoint/libECPoint.a)
set(POLYNOMIAL_LIB ${CMAKE_BINARY_DIR}/src/Polynomial/libPolynomial.a)
set(ASYMKEY_LIB ${CMAKE_BINARY_DIR}/src/AsymKey/libASymKey.a)
set(UTILS_LIB ${CMAKE_BINARY_DIR}/src/Utils/libUtils.a)
set(SECRET_SPLIT_LIB ${CMAKE_BINARY_DIR}/src/SecretShare/libSecretShare.a)

add_executable(asym_example asym_execute.cc)
target_include_directories(asym_example PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(asym_example pthread OpenSSL::Crypto ${ECPOINT_LIB} ${BIGNUMBERS_LIB} ${POLYNOMIAL_LIB} ${ASYMKEY_LIB} ${UTILS_LIB} ${SECRET_SPLIT_LIB})



