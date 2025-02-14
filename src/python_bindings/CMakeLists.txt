pybind11_add_module(PyNakasendo bignum_bindings.cc ecpoint_bindings.cc 
                    polynomial_bindings.cc interpolator_bindings.cc module_bindings_def.cc)

# Specify the static library location
#message(STATUS, "Top of the build tree: ${CMAKE_BINARY_DIR}")
set(BIGNUMBERS_LIB ${CMAKE_BINARY_DIR}/src/BigNumbers/libBigNumbers.a)
set(ECPOINT_LIB ${CMAKE_BINARY_DIR}/src/ECPoint/libECPoint.a)
set(POLYNOMIAL_LIB ${CMAKE_BINARY_DIR}/src/Polynomial/libPolynomial.a)
#message(STATUS, "CMAKE python bindings -> ${BIGNUMBERS_LIB}")


target_link_libraries(PyNakasendo PRIVATE OpenSSL::Crypto ${BIGNUMBERS_LIB} ${ECPOINT_LIB} ${POLYNOMIAL_LIB})

install(TARGETS PyNakasendo DESTINATION PyNakasendo)