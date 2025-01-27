pybind11_add_module(PyNakasendo bignum_bindings.cc)

# Specify the static library location
#message(STATUS, "Top of the build tree: ${CMAKE_BINARY_DIR}")
set(BIGNUMBERS_LIB ${CMAKE_BINARY_DIR}/src/BigNumbers/libBigNumbers.a)
#message(STATUS, "CMAKE python bindings -> ${BIGNUMBERS_LIB}")


target_link_libraries(PyNakasendo PRIVATE OpenSSL::Crypto ${BIGNUMBERS_LIB})

install(TARGETS PyNakasendo DESTINATION PyNakasendo)