#ifndef __KDF_H__
#define __KDF_H__

#include <string>

std::string GenerateKey(const std::string& , const std::string&, const int keylen=32, const int iterations=10000);
std::string GenerateNonce(const int blocksize=16);

#endif //#ifndef __KDF_H__
