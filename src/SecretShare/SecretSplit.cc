#include <string>
#include <ranges>
#include <Polynomial/Polynomial.h>
#include <BigNumbers/BigNumbers.h>
#include <Polynomial/LGInterpolator.h>
#include <SecretShare/KeyShare.h>
#include <SecretShare/SecretSplit.h>
#include <Utils/hashing.h>
#include <Utils/conversions.h>

std::string CreateUUID (){
    // Generate random value
    BigNumber ranVal;
    std::string uuidVal = ranVal.generateRandHex(32 * 8);
    size_t digest_len; 
    std::unique_ptr<unsigned char[]> digest_ptr = hash_msg_str(uuidVal,digest_len);
    std::string ret_uuid = binTohexStr(digest_ptr, digest_len); 
    return ret_uuid; 
}

std::vector<KeyShare> make_shared_secret (const Polynomial& poly, const int& minimum, const int& shares){
    //    Generates a random shamir pool, returns the secret and the share points.
    
    if (minimum > shares){
        throw std::runtime_error("pool secret would be irrecoverable");
    }
   
    std::string uuid = CreateUUID(); 
     
    std::vector<KeyShare> shareValues; 
    shareValues.reserve(shares); 
    std::ranges::generate_n(
        std::back_inserter(shareValues), shares, [&, i=1]() mutable{
            BigNumber xValue;
            xValue.FromDec(std::to_string(i));
            BigNumber val = poly(xValue);
            
            KeyShare share;
            share.k() = minimum;
            share.n() = shares;
            share.publicID() = uuid;
            share.Index() = xValue;
            share.Share() = val;
        
            ++i;
            return share;
        }
    );
    return shareValues ; 
}

BigNumber RecoverSecret ( const std::vector<KeyShare>& shares , const BigNumber& mod){
    if (shares.size() < 2){
        throw std::runtime_error("At least two shares are required to recover a secret");
    }
    // we need to build an std::vector<std::pair<BigNumber, BigNumber> > from the shares 
    std::vector<std::pair<BigNumber, BigNumber> > curvePoints;

    //const auto& first = shares.front();
    int k = shares.front().k(), n = shares.front().n();
    std::string uuid = shares.front().publicID();

    // Validate all shares belong to the same group
    if (!std::ranges::all_of(shares, [&](const KeyShare& s) {
        return s.k() == k && s.n() == n && s.publicID() == uuid;
    })) {
        throw std::runtime_error("Invalid share provided for share group");
    }

    // Transform shares into CurvePoints
    std::ranges::copy(
        shares | std::views::transform([](const KeyShare& s) {
            return std::pair<BigNumber, BigNumber>{s.Index(), s.Share()};
        }),
        std::back_inserter(curvePoints)
    );

    if(curvePoints.size() < k){
        throw std::runtime_error("inconsistant number of shares supplied: " + std::to_string(curvePoints.size()) + " less than " + std::to_string(k));
    }

    LGInterpolator interpFunc(curvePoints, mod);
    BigNumber zero;
    zero.Zero();
    BigNumber interpValViaFunc = interpFunc(zero); 
    return interpValViaFunc ; 
}