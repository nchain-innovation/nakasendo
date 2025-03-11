#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <pybind11/stl.h>
#include <BigNumbers/BigNumbers.h>
#include <Polynomial/Polynomial.h>
#include <SecretShare/KeyShare.h>
#include <SecretShare/SecretSplit.h>

void register_secretshare_bindings(pybind11::module_ &m){
    // Create a submodule for SecretShare-related functions
    pybind11::module_ secretshare_module = m.def_submodule("PySecretShare", "Submodule for secret sharing and key share generation functions");


    pybind11::class_<KeyShare>(secretshare_module, "PyKeyShare") 
        .def(pybind11::init<>()) // bind the constructor
        .def_property("k",
            [](const KeyShare& self) { return self.k(); },
            [](KeyShare &self, int value) { self.k() = value; }
        )
        .def_property("n",
            [](const KeyShare& self) { return self.n();},
            [](KeyShare &self, int value) {self.n() = value;}
        )
        . def_property("publicID",
            [](const KeyShare& self) { return self.publicID();},
            [](KeyShare& self, const std::string pubid){ self.publicID() = pubid;}
        ).def_property("Index",
            [](const KeyShare& self) {return self.Index();},
            [](KeyShare& self, BigNumber index){self.Index() = index;}
        )
        .def_property("Share",
            [](const KeyShare& self) {return self.Share();},
            [](KeyShare& self, BigNumber share){self.Share() = share;}
        );

    secretshare_module.def("to_toml", &to_toml, "Create a toml representation of the key share");
    secretshare_module.def("from_toml", &from_toml, "Create a key share object from a toml definition");

    secretshare_module.def("make_shared_secret", &make_shared_secret,
                            pybind11::arg("poly"), pybind11::arg("minimum"), pybind11::arg("shares"),
                            "Randomly generate a 256-bit number and split it into shares using the polynomial"); 
    
    secretshare_module.def("RecoverSecret", &RecoverSecret,
                            pybind11::arg("shares"), pybind11::arg("mod"),
                            "Recover Bignumber from a collection of shares");

    secretshare_module.def("CreateUUID", &CreateUUID, "Creating  UUID"); 
}
