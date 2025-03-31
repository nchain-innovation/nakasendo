#ifndef __BIG_NUMBERS_H__
#define __BIG_NUMBERS_H__


#include <vector>
#include <memory>
#include <iostream>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/objects.h>

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)> ; 
using CTX_ptr = std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;

class BigNumber
{
    friend BigNumber operator+ ( const BigNumber&, const BigNumber&);
    friend BigNumber operator+ ( const BigNumber&, const int&);
    friend BigNumber operator- (const BigNumber&, const BigNumber&);
    friend BigNumber operator- (const BigNumber&, const int&);

    friend BigNumber operator* (const BigNumber&, const BigNumber&);
    friend BigNumber operator/ (const BigNumber&, const BigNumber&);

    friend BigNumber operator% (const BigNumber&, const BigNumber&);
    friend bool operator> (const BigNumber&, const BigNumber& );
    friend bool operator< (const BigNumber&, const BigNumber& );
    friend bool operator== (const BigNumber&, const BigNumber& );

    friend BigNumber  operator>> (const BigNumber&, const BigNumber& );
    friend BigNumber  operator>> (const BigNumber&, const int& );
    friend BigNumber  operator<< (const BigNumber&, const BigNumber& );
    friend BigNumber  operator<< (const BigNumber&, const int& );

    // TODO implement operators with template expression allowing to write BigNumber r = (a+b)%n
    friend BigNumber Inv_mod (const BigNumber&  crARG, const BigNumber&  crMod);
    friend BigNumber Add_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);
    friend BigNumber Sub_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);
    friend BigNumber Mul_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);
    friend BigNumber Div_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);

    public:
        explicit BigNumber();
        ~BigNumber();
        //moveable
        BigNumber(BigNumber&& obj) noexcept;
        BigNumber& operator=(BigNumber&& obj) noexcept;
        //copyable
        BigNumber(const BigNumber& obj);
        BigNumber& operator=(const BigNumber& obj);

        // Set the value to one/zero/negative/positive
        void One(); 
        void Zero(); 
        void Negative () ; 
        void Positive ();

        // Pre/post inc/dec
        BigNumber operator++ (int);
        BigNumber& operator++ ();
        BigNumber operator-- (int);
        BigNumber& operator-- ();

        // public interface
        std::string ToHex () const ; 
        std::string ToDec () const ;

        int FromHex (const std::string& );
        int FromDec (const std::string& );

	    std::vector<uint8_t> ToBin () const;

	    int FromBin (unsigned char *val, int);
	    int FromBin (std::vector<uint8_t>&);

        // Generate & return string Representation
        std::string generateRandHex (const int& nsize=512) ; 
        std::string generateRandDec (const int& nsize=512) ; 
        std::string generateNegRandHex (const int& nsize=512);
        std::string generateNegRandDec (const int& nsize=512);
        std::string generateRandRange (const BigNumber&);

        
        void seedRNG (const std::string& ) ; 
        std::string generateRandHexWithSeed(const std::string&, const int& nsize=512); 
        std::string generateRandDecWithSeed(const std::string&, const int& nsize=512);
        std::string generateNegRandHexWithSeed (const std::string&, const int& nsize=512);
        std::string generateNegRandDecWithSeed (const std::string&, const int& nsize=512);
        std::string generateRangRandHexWithSeed (const std::string&, const BigNumber&);
        std::string generateRangRandDecWithSeed (const std::string&, const BigNumber&);

        // Generate random prime & return string Representation
        std::string generateRandPrimeHex(const int& nsize = 512);
        std::string generateRandPrimeDec(const int& nsize = 512);
        std::string generateRandPrimeHexWithSeed(const std::string& seed, const int& nsize = 512);
        std::string generateRandPrimeDecWithSeed(const std::string& seed, const int& nsize = 512);

        const BN_ptr& bn_ptr() const { return m_bn; }
        BN_ptr& bn_ptr() { return m_bn;}
        
        bool isPrime() const;

    private:

        BN_ptr m_bn; 
};

BigNumber GenerateOne ();
BigNumber GenerateZero () ;
BigNumber GenerateFromHex(const std::string&);

BigNumber GenerateRand ( const int& )  ;
BigNumber GenerateRandNegative (const int&);
BigNumber GenerateRandWithSeed(const std::string&, const int&);
BigNumber GenerateRandRange(const BigNumber& min, const BigNumber& max,const int& nsize=512);

BigNumber GenerateRandPrime(const int& nsize = 512);


// Explicitly declare the friend functions (to help the export to PyBind11) in the same namespace as BigNumber ()
BigNumber Inv_mod(const BigNumber& crARG, const BigNumber& crMod);
BigNumber Add_mod(const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);
BigNumber Sub_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);
BigNumber Mul_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);
BigNumber Div_mod (const BigNumber&  crLHS, const BigNumber&  crRHS, const BigNumber&  crMod);

std::unique_ptr<unsigned char []> S256HashMsgToChar(const std::string&,  size_t&);

#endif //ifndef __BIG_NUMBERS_H__


