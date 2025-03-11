#ifndef __SECRET_SPLIT_H__
#define __SECRET_SPLIT_H__

#include <string>
#include <vector>
#include <SecretShare/KeyShare.h>

class BigNumber;
class Polynomial;

std::vector<KeyShare> make_shared_secret (const Polynomial& poly, const int& minimum, const int& shares);
BigNumber RecoverSecret ( const std::vector<KeyShare>& shares , const BigNumber& mod);
std::string CreateUUID ();


#endif //#ifndef __SECRET_SPLIT_H__