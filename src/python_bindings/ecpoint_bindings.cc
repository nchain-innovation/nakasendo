#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <pybind11/stl.h>
#include <ECPoint/ECPoint.h>
#include <BigNumbers/BigNumbers.h>



void register_ecpoint_bindings(pybind11::module_ &m){

    // Create a submodule for ECPoint-related functions
    pybind11::module_ sub_module = m.def_submodule("PyECPoint", "Submodule for ECPoint related activity");


    pybind11::class_<ECPoint>(sub_module, "PyECPoint")
        .def(pybind11::init<>()) // bind the constructor
        .def(pybind11::init<int>()) // bind the constructor that takes an integer
        .def(pybind11::init<const ECPoint&>()) // Copy constructor
        .def("Double", &ECPoint::Double)
        .def("ToHex", &ECPoint::ToHex, pybind11::arg("compressed") = true)
        .def("SetRandom", &ECPoint::SetRandom)
        .def("Invert", &ECPoint::Invert)
        .def("CheckInfinity", &ECPoint::CheckInfinity)
        .def("CheckOnCurve", &ECPoint::CheckOnCurve)
        .def("GroupNid", &ECPoint::GroupNid)
        .def("GetAffineCoords", &ECPoint::GetAffineCoords)
        .def("GetECGroupOrder", &ECPoint::getECGroupOrder)
        .def("GetECGroupDegree", &ECPoint::getECGroupDegree)
        .def("GetGenerator", &ECPoint::getGenerator)
        .def("FromHex", &ECPoint::FromHex, pybind11::arg("hexStr"), pybind11::arg("nid") = -1)
        // Operators
        .def(pybind11::self + pybind11::self)
        .def(pybind11::self == pybind11::self)
        .def(pybind11::self != pybind11::self)
        //.def(pybind11::self * pybind11::other<BigNumber>())
        .def("__mul__", [](const ECPoint& p, const BigNumber& n) {
            return p * n; // Calls the friend operator* 
        }, pybind11::is_operator())
        .def("__repr__",
            [](const ECPoint &a){
                return a.ToHex();
            });
    

    sub_module.def("MultiplyByGeneratorPt", &MultiplyByGeneratorPt, pybind11::arg("value"), pybind11::arg("curveID") = 714, "Multiply BigNumber By GeneratorPr");
    sub_module.def("GroupOrder", &GroupOrder, "Return the Group Order");
    sub_module.def("GetCurveList", &getCurveList, "Return a list of curves");
    sub_module.def("GetNidForString", &getNidForString, "Return a curve NID given a curve name");
    sub_module.def("Multiply", &Multiply, "Eliptic Curve multiplication G * n + m * q, when m & n are bignumbers and q is an EC Point");

    //ECPoint GenerateFromHex(const std::string& hexval, const int curveID){
    sub_module.def("GenerateECFromHex", &GenerateECFromHex, pybind11::arg("hexval"), pybind11::arg("curveID") = 714, "Generate an EC Point from the hexvalue on a given curve");
}
