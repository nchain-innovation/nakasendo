#include <openssl/evp.h>
#include <openssl/rand.h>
#include "kdf.h"
#include "conversions.h"

std::string GenerateNonce(const int blocksize){
    std::unique_ptr<unsigned char[]> nonce_ptr(new unsigned char[blocksize]);
    int rc = RAND_bytes(nonce_ptr.get(), blocksize);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes for iv failed"); 
    
    return binTohexStr(nonce_ptr, blocksize);
}

std::string GenerateKey(const std::string& pw, const std::string& nonce, int keylen, int iterations){
    std::unique_ptr<unsigned char[]> key_ptr(new unsigned char[keylen]); 
    std::unique_ptr<unsigned char[]> pw_ptr(new unsigned char[pw.size()]); 
    std::unique_ptr<unsigned char[]> nonce_ptr(new unsigned char[nonce.size()]); 

    std::copy(pw.begin(), pw.end(), pw_ptr.get());
    std::copy(nonce.begin(), nonce.end(), nonce_ptr.get()); 
    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *> (pw_ptr.get()), pw.size(),
                            nonce_ptr.get(), nonce.size(),
                            iterations, EVP_sha256(), keylen,
                            key_ptr.get())) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }
    return binTohexStr(key_ptr, keylen);
}

