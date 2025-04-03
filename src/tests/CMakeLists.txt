find_package(GTest REQUIRED)
# set up library inlcude paths
link_directories(${CMAKE_BINARY_DIR}/src/BigNumbers
                ${CMAKE_BINARY_DIR}/src/ECPoint
                ${CMAKE_BINARY_DIR}/src/Polynomial
                ${CMAKE_BINARY_DIR}/src/AsymKey
                ${CMAKE_BINARY_DIR}/src/SecretShare
                ${CMAKE_BINARY_DIR}/src/Utils)

add_executable(test_big_numbers test_BigNumbers.cc)
target_link_libraries(test_big_numbers GTest::gtest_main pthread OpenSSL::Crypto -lBigNumbers)

add_executable(test_ec_point test_ECPoints.cc)
target_link_libraries(test_ec_point GTest::gtest_main pthread OpenSSL::Crypto -lECPoint -lBigNumbers)

set(POLYNOMIAL_LIB ${CMAKE_BINARY_DIR}/src/Polynomial/libPolynomial.a)
add_executable(test_polynomial test_Polynomial.cc)
target_link_libraries(test_polynomial GTest::gtest_main pthread OpenSSL::Crypto -lECPoint -lBigNumbers -lPolynomial)

add_executable(test_asym_key test_AsymKey.cc)
target_link_libraries(test_asym_key GTest::gtest_main pthread OpenSSL::Crypto -lECPoint -lBigNumbers -lASymKey -lUtils -lSecretShare -lPolynomial)

add_executable(test_secret_split test_SecretSplit.cc)
target_link_libraries(test_secret_split GTest::gtest_main pthread OpenSSL::Crypto -lASymKey -lSecretShare -lPolynomial -lECPoint -lBigNumbers -lUtils)

include(GoogleTest)
# Discover individual test cases and register them with CTest
gtest_discover_tests(test_big_numbers)
gtest_discover_tests(test_ec_point)
gtest_discover_tests(test_polynomial)
gtest_discover_tests(test_asym_key)
gtest_discover_tests(test_secret_split)