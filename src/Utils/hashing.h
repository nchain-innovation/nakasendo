#ifndef __HASHING_H__
#define __HASHING_H__

#include <openssl/evp.h>
#include <memory>
#include <array>

// Template function for hashing messages with a configurable hash function
template <const EVP_MD* (*HashFunc)() = EVP_sha256>
std::unique_ptr<unsigned char[]> hash_msg_str(const std::string& input_msg, size_t& len);

template <const EVP_MD* (*HashFunc)() = EVP_sha256>
std::unique_ptr<unsigned char[]> hash_msg_bytes(const std::unique_ptr<unsigned char[]>&, const size_t&, size_t&);


std::array<unsigned char, 32> double_sha256_str(const std::string&);
std::array<unsigned char, 32> double_sha256_bytes(const std::unique_ptr<unsigned char[]>&, const size_t&);

//start here in tomorrow 
//2 functions  that take string/bytes , return bytes (std::array<unsigned char, 20>), ripd160(sha256(bytes) & ripd160(sha256(str))
#endif //#ifndef __HASHING_H__
