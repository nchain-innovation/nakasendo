#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <pybind11/stl.h>
#include <ECPoint/ECPoint.h>
#include <BigNumbers/BigNumbers.h>
#include <Polynomial/Polynomial.h>
#include <Polynomial/LGInterpolator.h>
#include <vector>
#include <sstream>


void register_lginterpolator_bindings(pybind11::module_ &m){
    pybind11::class_<LGInterpolator>(m, "PyLGInterpolator>")
        .def(pybind11::init<std::vector<std::pair<BigNumber,BigNumber>>&, const BigNumber&>())
        .def("__call__", 
            pybind11::overload_cast<const BigNumber&>(&LGInterpolator::operator()), pybind11::arg("x"))
        .def("__call__",
            pybind11::overload_cast<const int&, const BigNumber&>(&LGInterpolator::operator()), 
            pybind11::arg("index"), pybind11::arg("x"))
        .def("degree", &LGInterpolator::Degree)
        .def("length", &LGInterpolator::Length)
        .def("__repr__",
            [](const LGInterpolator &p) {
                std::ostringstream oss;
                oss << p;
                return oss.str();
            });
}

void register_lgecinterpolator_bindings(pybind11::module_ &m){
    pybind11::class_<LGECInterpolator>(m, "PyLGECInterpolator>")
        .def(pybind11::init<std::vector<std::pair<BigNumber, ECPoint>>&, const BigNumber&>())
        .def("__call__",
            pybind11::overload_cast<const BigNumber&, const int&>(&LGECInterpolator::operator()),
            pybind11::arg("xValue"), pybind11::arg("curve_id"))
        .def("__call__",
            pybind11::overload_cast<const int&, const BigNumber&>(&LGECInterpolator::operator()),
            pybind11::arg("i"), pybind11::arg("xValue"))
        .def("Degree", &LGECInterpolator::Degree)
        .def("Length", &LGECInterpolator::Length)
        .def("__repr__",
            [](const LGECInterpolator &p) {
                std::ostringstream oss;
                oss << p;
                return oss.str();
            });
}

