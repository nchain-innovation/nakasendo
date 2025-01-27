#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <BigNumbers/BigNumbers.h>

PYBIND11_MODULE(PyNakasendo, m){
    m.doc() = "pybind11 Nakasendo plugin";
   // m.def("add", &add, "A function that adds two ints");
   // m.def("bn_rand_test", &bn_rand_test, "A function to generate a large random number");


    //m.def("create_bignum", []() {
    //    return random_int();  // Convert back to Python int (to check round trip conversion)
    //});
    pybind11::class_<BigNumber>(m, "PyBigNumber")
        .def(pybind11::init<>()) // bind the constructor
        .def(pybind11::init<const BigNumber&>()) // Copy constructor
        .def("One", &BigNumber::One)
        .def("Zero",  &BigNumber::Zero)
        .def("ToHex", &BigNumber::ToHex)
        .def("ToDec", &BigNumber::ToDec)
        .def("GenerateRandHex", &BigNumber::generateRandHex)
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
            });
        // Wrap the GenerateOne function
    m.def("GenerateOne", &GenerateOne, "Generate a BigNumber with the value of one");
    m.def("GenerateZero", &GenerateZero, "Generate a BigNumber with the value of zero");
    m.def("GenerateRandRange", &GenerateRandRange, "Generate a BigNumber within a range");
    m.def("GenerateRandPrime", &GenerateRandPrime, "Generate a Random prime of size 512");
}
