find_package(GTest REQUIRED)
set(BIGNUMBERS_LIB ${CMAKE_BINARY_DIR}/src/BigNumbers/libBigNumbers.a)
add_executable(test_big_numbers test_BigNumbers.cc)
target_link_libraries(test_big_numbers GTest::gtest_main pthread OpenSSL::Crypto ${BIGNUMBERS_LIB})

set(ECPOINT_LIB ${CMAKE_BINARY_DIR}/src/ECPoint/libECPoint.a)
add_executable(test_ec_point test_ECPoints.cc)
target_link_libraries(test_ec_point GTest::gtest_main pthread OpenSSL::Crypto ${ECPOINT_LIB} ${BIGNUMBERS_LIB})

set(POLYNOMIAL_LIB ${CMAKE_BINARY_DIR}/src/Polynomial/libPolynomial.a)
add_executable(test_polynomial test_Polynomial.cc)
target_link_libraries(test_polynomial GTest::gtest_main pthread OpenSSL::Crypto ${ECPOINT_LIB} ${BIGNUMBERS_LIB} ${POLYNOMIAL_LIB})

set(ASYMKEY_LIB ${CMAKE_BINARY_DIR}/src/AsymKey/libASymKey.a)
set(UTILS_LIB ${CMAKE_BINARY_DIR}/src/Utils/libUtils.a)

add_executable(test_asym_key test_AsymKey.cc)
target_link_libraries(test_asym_key GTest::gtest_main pthread OpenSSL::Crypto ${ECPOINT_LIB} ${BIGNUMBERS_LIB} ${POLYNOMIAL_LIB} ${ASYMKEY_LIB} ${UTILS_LIB})

include(GoogleTest)
# Discover individual test cases and register them with CTest
gtest_discover_tests(test_big_numbers)
gtest_discover_tests(test_ec_point)
gtest_discover_tests(test_polynomial)
gtest_discover_tests(test_asym_key)