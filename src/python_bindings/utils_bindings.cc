#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <pybind11/stl.h>
#include <Utils/hashing.h>
#include <Utils/conversions.h>
#include <Utils/kdf.h>

pybind11::bytes py_double_sha256(pybind11::bytes input) {
    std::string input_str = input;  
    size_t len = input_str.size();

    auto data = std::make_unique<unsigned char[]>(len);
    std::memcpy(data.get(), input_str.data(), len);

    std::array<unsigned char, 32> hash = double_sha256_bytes(data, len);

    return pybind11::bytes(reinterpret_cast<const char*>(hash.data()), hash.size());
}


pybind11::bytes hash_msg_sha512_str(const std::string& input_msg) {
    size_t len = 0;
    std::unique_ptr<unsigned char[]> hash = hash_msg_str<EVP_sha512>(input_msg, len);
    return pybind11::bytes(reinterpret_cast<const char*>(hash.get()), len);
}

pybind11::bytes hash_msg_sha512_bytes(pybind11::bytes input) {
    size_t len = 0;
    std::string input_str = input;
    auto input_digest = std::make_unique<unsigned char[]>(input_str.size());
    std::memcpy(input_digest.get(), input_str.data(), input_str.size());

    std::unique_ptr<unsigned char[]> hash = hash_msg_bytes<EVP_sha512>(input_digest, input_str.size(), len);
    return pybind11::bytes(reinterpret_cast<const char*>(hash.get()), len);
}

pybind11::bytes hash_msg_sha256_str(const std::string& input_msg) {
    size_t len = 0;
    std::unique_ptr<unsigned char[]> hash = hash_msg_str<EVP_sha256>(input_msg, len);
    return pybind11::bytes(reinterpret_cast<const char*>(hash.get()), len);
}

pybind11::bytes hash_msg_sha256_bytes(pybind11::bytes input) {
    size_t len = 0;
    std::string input_str = input; 
    auto input_digest = std::make_unique<unsigned char[]>(input_str.size());
    std::memcpy(input_digest.get(), input_str.data(), input_str.size());
    
    std::unique_ptr<unsigned char[]> hash = hash_msg_bytes<EVP_sha256>(input_digest,input_str.size(), len);
    return pybind11::bytes(reinterpret_cast<const char*>(hash.get()), len);
}


void register_utils_bindings(pybind11::module_ &m){
    pybind11::module_ utils_module = m.def_submodule("Utils", "Submodule for utility functions");
    utils_module.def("double_sha256", &py_double_sha256, "Compute double SHA-256");
    utils_module.def("hash_sha256_str", &hash_msg_sha256_str, "Compute SHA-256 hash of a string message, returns 32-byte array");
    utils_module.def("hash_sha256_bytes", &hash_msg_sha256_bytes, "Compute SHA-256 hash of a byte-array, returns 32-byte array");
    utils_module.def("hash_sha512_str", &hash_msg_sha512_str, "Compute SHA-512 hash of a string message, returns 64-byte array");
    utils_module.def("hash_sha512_bytes", &hash_msg_sha512_bytes, "Compute SHA-512 hash of a byte-array, returns 64-byte array");
    utils_module.def("GenerateNonce", &GenerateNonce, pybind11::arg("blocksize") = 16,  "Generate a random nonce of a given size, defaults to 16-bits");
    utils_module.def("GenerateKey", &GenerateKey, pybind11::arg("pw"), pybind11::arg("nonce"), pybind11::arg("keylen") = 32, pybind11::arg("iterations") = 10000,"Generate a key using PBKDF2 with SHA-256, defaults to 256 bit key with 10000 iterations");
}
