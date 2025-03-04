#ifndef __UTILS_H__
#define __UTILS_H__

#include <memory>
std::unique_ptr<unsigned char[]> HexStrToBin(const std::string& input, size_t& len);
std::string binTohexStr(const std::unique_ptr<unsigned char[]>& data, const size_t& len);

#endif //#ifndef __UTILS_H__