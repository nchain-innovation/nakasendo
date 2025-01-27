#ifndef __BIG_NUMBERS_H__
#define __BIG_NUMBERS_H__


#include <memory>
#include <string>
#include <vector>

class BigNumberImpl; 

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

        bool isPrime() const;
        
    private:
        const BigNumberImpl* pImpl() const { return m_pImpl.get(); }
        BigNumberImpl* pImpl() {return m_pImpl.get();}       

        std::unique_ptr<BigNumberImpl> m_pImpl ; 
};

BigNumber GenerateOne ();
BigNumber GenerateZero () ;

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
#endif //ifndef __BIG_NUMBERS_H__


