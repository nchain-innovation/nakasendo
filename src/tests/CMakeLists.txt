find_package(GTest REQUIRED)
set(BIGNUMBERS_LIB ${CMAKE_BINARY_DIR}/src/BigNumbers/libBigNumbers.a)
add_executable(test_big_numbers test_BigNumbers.cc)
target_link_libraries(test_big_numbers GTest::gtest_main pthread OpenSSL::Crypto ${BIGNUMBERS_LIB})


include(GoogleTest)
# Discover individual test cases and register them with CTest
gtest_discover_tests(test_big_numbers)