pybind11_add_module(PyNakasendo bignum_helper.h bignum_helper.cc bignum_bindings.cc ecpoint_bindings.cc 
                    polynomial_bindings.cc interpolator_bindings.cc module_bindings_def.cc
                    asymkey_bindings.cc utils_bindings.cc keyshare_bindings.cc)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Specify the static library location
#message(STATUS, "Top of the build tree: ${CMAKE_BINARY_DIR}")
set(BIGNUMBERS_LIB ${CMAKE_BINARY_DIR}/src/BigNumbers/libBigNumbers.a)
set(ECPOINT_LIB ${CMAKE_BINARY_DIR}/src/ECPoint/libECPoint.a)
set(POLYNOMIAL_LIB ${CMAKE_BINARY_DIR}/src/Polynomial/libPolynomial.a)
set(ASYMKEY_LIB ${CMAKE_BINARY_DIR}/src/AsymKey/libASymKey.a)
set(UTILS_LIB ${CMAKE_BINARY_DIR}/src/Utils/libUtils.a)
set(SECRET_SHARE_LIB ${CMAKE_BINARY_DIR}/src/SecretShare/libSecretShare.a)

target_link_libraries(PyNakasendo PRIVATE OpenSSL::Crypto ${BIGNUMBERS_LIB} ${ECPOINT_LIB} ${POLYNOMIAL_LIB} ${ASYMKEY_LIB} ${UTILS_LIB} ${SECRET_SHARE_LIB})

install(TARGETS PyNakasendo DESTINATION PyNakasendo)