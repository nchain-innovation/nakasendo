#include <hashing.h>
#include <string>

using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

template <const EVP_MD* (*HashFunc)()>
std::unique_ptr<unsigned char[]> hash_msg_str(const std::string& input_msg, size_t& len){
    std::unique_ptr<unsigned char[]> input_bytes(new unsigned char[input_msg.size()]);
    std::copy(input_msg.begin(), input_msg.end(), input_bytes.get());
    std::unique_ptr<unsigned char[]> hash = hash_msg_bytes<HashFunc>(input_bytes, input_msg.size(), len); 
    return hash; 
}

template <const EVP_MD* (*HashFunc)()>
std::unique_ptr<unsigned char[]> hash_msg_bytes(const std::unique_ptr<unsigned char[]>& msg, const size_t& msg_len,  size_t& len) {
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    // Initialize digest context with the chosen hash function
    if (EVP_DigestInit_ex(md_ctx.get(), HashFunc(), nullptr) != 1)
        throw std::runtime_error("EVP_DigestInit_ex failed");

    std::unique_ptr<unsigned char[]> digest(new unsigned char[EVP_MAX_MD_SIZE]);

    // Update with data
    if (EVP_DigestUpdate(md_ctx.get(), msg.get(), msg_len) != 1)
        throw std::runtime_error("EVP_DigestUpdate failed");

    // Finalize and get the hash
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(md_ctx.get(), digest.get(), &hash_len) != 1)
        throw std::runtime_error("EVP_DigestFinal_ex failed");

    len = hash_len;
    return digest;
}

std::array<unsigned char, 32> double_sha256_str(const std::string& input_msg){
    std::unique_ptr<unsigned char[]> input_bytes(new unsigned char[input_msg.size()]);
    std::copy(input_msg.begin(), input_msg.end(), input_bytes.get());
    return double_sha256_bytes(input_bytes, input_msg.size());
}

std::array<unsigned char, 32> double_sha256_bytes(const std::unique_ptr<unsigned char[]>& data, const size_t& len){
    std::array<unsigned char, 32> hash1, hash2;

    // Create an OpenSSL context for SHA-256
    EVP_MD_CTX_ptr ctx( EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Failed to create OpenSSL digest context");
    }

    // First SHA-256
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.get(), len) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), hash1.data(), nullptr) != 1)
        throw std::runtime_error("Error computing first SHA-256");

    // Second SHA-256
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), hash1.data(), hash1.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), hash2.data(), nullptr) != 1) {
        throw std::runtime_error("Error computing second SHA-256");
    }

    return hash2;
}

// Explicitly instantiate the template for EVP_sha256 (or other hash functions)
template std::unique_ptr<unsigned char[]> hash_msg_bytes<EVP_sha256>(const std::unique_ptr<unsigned char[]>& msg, const size_t& msg_len, size_t& len);
template std::unique_ptr<unsigned char[]> hash_msg_str<EVP_sha256>(const std::string& input_msg, size_t& len);

template std::unique_ptr<unsigned char[]> hash_msg_bytes<EVP_sha512>(const std::unique_ptr<unsigned char[]>& msg, const size_t& msg_len, size_t& len);
template std::unique_ptr<unsigned char[]> hash_msg_str<EVP_sha512>(const std::string& input_msg, size_t& len);

