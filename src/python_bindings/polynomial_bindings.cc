#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <pybind11/stl.h>
#include <ECPoint/ECPoint.h>
#include <BigNumbers/BigNumbers.h>
#include <Polynomial/Polynomial.h>
#include <sstream>

void register_polynomial_bindings(pybind11::module_ &m){
    pybind11::class_<Polynomial>(m, "PyPolynomial")
        .def(pybind11::init<>()) // bind the default constructor
         // Constructor: from vector of BigNumber & modulo
        .def(pybind11::init<std::vector<BigNumber>&, const BigNumber&>(), pybind11::arg("coefficients"), pybind11::arg("modulo"))
        // construct from random numbers
        .def(pybind11::init<int, const BigNumber&>(), pybind11::arg("degree"), pybind11::arg("modulo"))
        .def(pybind11::init<int, const BigNumber&, const BigNumber&>(), pybind11::arg("degree"), pybind11::arg("modulo"), pybind11::arg("a_0")) 
        //Copy constructor and assignment
        .def(pybind11::init<const Polynomial&>())
        .def("assign", [](Polynomial &self, const Polynomial &other) { self = other; })
        .def("getDegree", &Polynomial::getDegree)
        // Get coefficients
        .def("get_coefficients", &Polynomial::getCoefficients, pybind11::return_value_policy::reference)
        // Get length
        .def("length", &Polynomial::length)
        // Indexing operator []
        .def("__getitem__", [](const Polynomial &p, unsigned int index) {
            if (index >= p.length()) throw pybind11::index_error("Index out of range");
            return p[index];
        }, pybind11::arg("index"))

        // Function call operator ()
        .def("__call__", &Polynomial::operator(), pybind11::arg("x"))

        // Hide polynomial coefficients
        .def("hide", &Polynomial::hide, pybind11::arg("curveID") = 714)
        .def("hide_as_point", &Polynomial::hideAsPoint, pybind11::arg("curveID") = 714)

        .def("__repr__",
            [](const Polynomial &p) {
                std::ostringstream oss;
                oss << p;
                return oss.str();
            });
}
