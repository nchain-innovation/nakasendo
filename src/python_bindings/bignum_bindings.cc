#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <BigNumbers/BigNumbers.h>
#include <bignum_helper.h>

void register_bignum_bindings(pybind11::module_ &m){

    // Create a submodule for AsymKey-related functions
    pybind11::module_ sub_module = m.def_submodule("PyBigNumber", "Submodule for BigNum related activity");


    pybind11::class_<BigNumber>(sub_module, "PyBigNumber")
        .def(pybind11::init<>()) // bind the constructor
        .def(pybind11::init<const BigNumber&>()) // Copy constructor
        .def("One", &BigNumber::One)
        .def("Zero",  &BigNumber::Zero)
        .def("ToHex", &BigNumber::ToHex)
        .def("ToDec", &BigNumber::ToDec)
        .def("GenerateRandHex", &BigNumber::generateRandHex, pybind11::arg("nsize") = 512)
        .def("GenerateRandDec", &BigNumber::generateRandDec)
        .def("GenerateNegRandHex", &BigNumber::generateNegRandHex)
        .def("GenerateNegRandDec", &BigNumber::generateNegRandDec)
        .def("FromHex", &BigNumber::FromHex)
        .def("FromDec", &BigNumber::FromDec)
        // Operators
        .def(pybind11::self + pybind11::self)
        .def(pybind11::self + int())
        .def(pybind11::self - pybind11::self)
        .def(pybind11::self - int())
        .def(pybind11::self * pybind11::self)
        .def(pybind11::self / pybind11::self)
        .def(pybind11::self % pybind11::self)
        .def(pybind11::self > pybind11::self)
        .def(pybind11::self < pybind11::self)
        .def(pybind11::self == pybind11::self)
        .def(pybind11::self >> pybind11::self)
        .def(pybind11::self >> int())
        .def(pybind11::self << pybind11::self)
        .def(pybind11::self << int())
        .def_static("Inv_mod", &Inv_mod)
        .def_static("Add_mod", &Add_mod)
        .def_static("Sub_mod", &Sub_mod)
        .def_static("Mul_mod", &Mul_mod)
        .def_static("Div_mod", &Div_mod)
        .def("__repr__",
            [](const BigNumber &a){
                return a.ToHex();
            })
        .def("__hash__", [](const BigNumber &a) {
            return std::hash<std::string>{}(a.ToHex());
        });
        // Wrap the GenerateOne function
    sub_module.def("GenerateOne", &GenerateOne, "Generate a BigNumber with the value of one");
    sub_module.def("GenerateZero", &GenerateZero, "Generate a BigNumber with the value of zero");
    sub_module.def("GenerateFromHex", &GenerateFromHex, pybind11::arg("hexval"), "Create a BigNumber from the hex value"); 
    sub_module.def("GenerateRandRange", &GenerateRandRange, "Generate a BigNumber within a range");
    sub_module.def("GenerateRandPrime", &GenerateRandPrime, pybind11::arg("nsize") = 512, "Generate a Random prime default is 512 bits");
    sub_module.def("GenerateRand", &GenerateRand,  pybind11::arg("nsize") = 512, "Generate a Random number default is 512 bits");
    sub_module.def("PyIntToBigNumber", &PyIntToBigNumber, "Generate a BigNumber from a python integer");
}
