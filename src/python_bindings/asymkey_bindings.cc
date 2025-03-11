#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <pybind11/stl.h>
#include <AsymKey/AsymKey.h>
#include <ECPoint/ECPoint.h>
#include <BigNumbers/BigNumbers.h>

void register_asymkey_bindings(pybind11::module_ &m){
    // Create a submodule for AsymKey-related functions
    pybind11::module_ asymkey_module = m.def_submodule("PyAsymKey", "Submodule for asymmetric key functions");


    //pybind11::class_<AsymKey>(m, "PyAsymKey")
    pybind11::class_<AsymKey>(asymkey_module, "PyAsymKey")
        .def(pybind11::init<>()) // bind the constructor
        .def(pybind11::init<int>(), pybind11::arg("groupNID")) // bind the constructor that takes an integer
        .def("is_valid", &AsymKey::is_valid)
        .def("GroupNid", &AsymKey::GroupNid)
        .def("Group_G", &AsymKey::Group_G)
        .def("Group_p", &AsymKey::Group_p)
        .def("Group_a", &AsymKey::Group_a)
        .def("Group_b", &AsymKey::Group_b)
        .def("Group_Order", &AsymKey::Group_Order)
        .def("exportPublicKey", &AsymKey::exportPublicKey)
        .def("exportPrivateKey", &AsymKey::exportPrivateKey)
        .def("exportPublicKeyPEM", &AsymKey::exportPublicKeyPEM)
        .def("exportPrivateKeyPEM", &AsymKey::exportPrivateKeyPEM)
        .def("sign", &AsymKey::sign, pybind11::arg("crMsg"))
        .def("sign_S256_str", &AsymKey::sign_S256_str, pybind11::arg("inputHash"))
        .def("sign_S256_bytes", [](const AsymKey& self, pybind11::bytes data) {
            // Convert Python bytes to std::vector<unsigned char>
            std::string data_str = data;  // Extract bytes as std::string
            size_t len = data_str.size();

            // Allocate a unique_ptr with data copied into it
            auto unique_data = std::make_unique<unsigned char[]>(len);
            std::memcpy(unique_data.get(), data_str.data(), len);

            // Call the actual function
            auto result = self.sign_S256_bytes(unique_data, len);

            return std::make_tuple(result.first, result.second);
        }, pybind11::arg("msg"),
        "Sign a SHA-256 message as raw bytes and return (r, s).")
        .def("__repr__",
            [](const AsymKey &key) {
                std::ostringstream oss;
                oss << key.exportPublicKey().ToHex();
                return oss.str();
            });
    asymkey_module.def("FromPemStr", &FromPemStr, "Create an Asymkey from a PEM string");
    asymkey_module.def("verify", &verify, pybind11::arg("crMsg"), pybind11::arg("crPublicKeyPEMStr"), pybind11::arg("rs"), "Verify a message with a public key and signature. The message is hashed with SHA256");
    asymkey_module.def("verify_S256_str", &verify_S256_str, pybind11::arg("crMsg"), pybind11::arg("crPublicKeyPEMStr"), pybind11::arg("rs"), "Verify a message with a public key and signature. The message MUST BE pre-hashed with SHA256");
    asymkey_module.def("DEREncodedSignature", [](const BigNumber& r, const BigNumber& s) -> pybind11::bytes{
        size_t len(-1);
        std::unique_ptr<unsigned char[]>  sigDER = DEREncodedSignature(r,s,len);
        return pybind11::bytes(reinterpret_cast<const char*>(sigDER.get()), len);
    }, pybind11::arg("r"), pybind11::arg("s"), "Return the DER encoded signature");

    asymkey_module.def("verify_S256_bytes", [](pybind11::bytes msg, 
                                                const std::string& public_key_pem,
                                                const std::pair<BigNumber, BigNumber>& rs) 
                                            -> bool {
        std::string msg_str = msg;  // Extract bytes as std::string
        size_t len = msg_str.size();

        // Allocate a unique_ptr with data copied into it
        auto msg_bytes = std::make_unique<unsigned char[]>(len);
        std::memcpy(msg_bytes.get(), msg_str.data(), len);

        // Call the actual function
        return verify_S256_bytes(msg_bytes, len, public_key_pem, rs);
    }, pybind11::arg("msg"), pybind11::arg("public_key_pem"), pybind11::arg("rs"),
    "Verify a SHA-256 signed message given public key and signature (r, s).");

    AsymKey FromBigNumber(const BigNumber&, const int& curveID=714); 
    asymkey_module.def("FromBigNumber", &FromBigNumber, pybind11::arg("bn_priv"), pybind11::arg("curveID")=714,
    "Create an AsymKey from a set of shares created on a curve");
}
