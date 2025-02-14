#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 

// Function to register BigNumber bindings in PyBind11
void register_bignum_bindings(pybind11::module_ &m);
void register_ecpoint_bindings(pybind11::module_ &m);
void register_polynomial_bindings(pybind11::module_ &m); 
void register_lginterpolator_bindings(pybind11::module_ &m); 
void register_lgecinterpolator_bindings(pybind11::module_ &m);

PYBIND11_MODULE(PyNakasendo, m){
    register_bignum_bindings(m); 
    register_ecpoint_bindings(m);
    register_polynomial_bindings(m); 
    register_lginterpolator_bindings(m); 
    register_lgecinterpolator_bindings(m); 
}
