#include <BigNumbers/BigNumbers.h>
#include <openssl/rand.h>

#include <iostream>
#include <sstream>
#include <stdlib.h>

#include <cassert>

inline void help_openssl_free_char(char* p) { OPENSSL_free(p); }
inline void help_openssl_free_uchar(unsigned char* p) { OPENSSL_free(p); }

BigNumber::BigNumber() : m_bn (BN_new(), ::BN_free) {return;}

BigNumber::~BigNumber()=default;

BigNumber::BigNumber(BigNumber&& obj) noexcept = default;
BigNumber& BigNumber::operator=(BigNumber&& obj) noexcept = default;

BigNumber::BigNumber(const BigNumber& obj) 
    : m_bn(BN_new(), ::BN_free){ 
        BN_copy (m_bn.get(), obj.m_bn.get());
}


BigNumber& BigNumber::operator=(const BigNumber& obj){
    if (this != &obj){
        BN_copy(m_bn.get(), obj.m_bn.get());      
    }
    return *this;
}

void BigNumber::One(){
    BN_one (m_bn.get());
}

void BigNumber::Zero(){
    BN_zero (m_bn.get());
}   

void BigNumber::Negative(){
    BN_set_negative(m_bn.get(), 1);
}

BigNumber BigNumber::operator++ (int){
    BigNumber num(*this);
    ++ (*this); 
    return num ; 
    
}

BigNumber& BigNumber::operator++(){
    BN_ptr res (BN_new(),::BN_free);
    BN_one(res.get());
    if(!BN_add(m_bn.get(),m_bn.get(), res.get()))
        throw std::runtime_error("Unable to increment by one");
    return *this ; 
}


BigNumber BigNumber::operator-- (const int){
    BigNumber bnVal(*this);
    -- (*this);
    return bnVal;
}

BigNumber& BigNumber::operator--()
{
    BN_ptr res (BN_new(),::BN_free);
    BN_one(res.get());
    if(!BN_sub(m_bn.get(),m_bn.get(), res.get()))
        throw std::runtime_error("Unable to decrement by one");
    return *this ; 
}


std::string BigNumber::ToHex () const {
    using SSL_CharPtr = std::unique_ptr<char, decltype(&help_openssl_free_char)>;
    SSL_CharPtr hex_str(BN_bn2hex(m_bn.get()), &help_openssl_free_char);
    std::string ret_str (hex_str.get());
    return ret_str;
}

std::string BigNumber::ToDec () const{
    using SSL_CharPtr = std::unique_ptr<char, decltype(&help_openssl_free_char)>;
    SSL_CharPtr dec_str(BN_bn2dec(m_bn.get()), &help_openssl_free_char);
    std::string ret_str(dec_str.get());
    return ret_str;
}

int BigNumber::FromHex (const std::string& val){
    BIGNUM * ptr = m_bn.get () ; 
    return(BN_hex2bn(&ptr, val.c_str()));
}

int BigNumber::FromDec (const std::string& val)
{
    BIGNUM * ptr = m_bn.get () ; 
    return(BN_dec2bn (&ptr, val.c_str()));
}

int BigNumber::FromBin (unsigned char *val, int size)
{
    if (val == NULL || size <=0)
	    return -1;
    // convert bin val to Big number
    if (BN_bin2bn(val, size,  m_bn.get()) == nullptr)
        return -1;
    return 1;
}

int BigNumber::FromBin (std::vector<uint8_t>& val)
{
    if (val.size() == 0)
	    return -1;

    // get the raw data from the vector
    unsigned char *valData = val.data();
    
    // get bin value to BN
    return FromBin(valData, (int)val.size());
}

std::vector<uint8_t> BigNumber::ToBin () const
{
    using SSL_UCharPtr = std::unique_ptr<unsigned char, decltype(&help_openssl_free_uchar)>;
    size_t len = BN_num_bytes(m_bn.get());
    SSL_UCharPtr binBn((unsigned char *)OPENSSL_malloc(len), &help_openssl_free_uchar);
    if (!binBn.get())
        return std::vector<uint8_t>();

    size_t ret = BN_bn2bin(m_bn.get(), binBn.get());
    if (ret != len)
        return std::vector<uint8_t>();

    std::vector<uint8_t>  retVec(binBn.get(), binBn.get()+ret);
    return retVec;
}

std::string BigNumber::generateRandHex(const int& nsize){
    if (!BN_rand(m_bn.get(), nsize, 0,0)){
        std::stringstream msg ; 
        msg << "error generating random number of size -> " << nsize; 
        throw std::runtime_error(msg.str()); 
    }
    return ToHex ();
} 

std::string BigNumber::generateRandDec(const int& nsize){
    if (!BN_rand(m_bn.get(), nsize, 0,0))
        throw std::runtime_error("error generating random number"); 
    return ToDec();
}

std::string BigNumber::generateNegRandHex (const int& nsize){
   if (!BN_rand(m_bn.get(), nsize, 0,0))
        throw std::runtime_error("error generating random number"); 
    Negative();
    return ToHex();
}

std::string BigNumber::generateNegRandDec (const int& nsize){
   if (!BN_rand(m_bn.get(), nsize, 0,0))
        throw std::runtime_error("error generating random number"); 
    Negative();
    return ToDec();
}

std::string BigNumber::generateRandRange (const BigNumber& max){       
     // seed the PRNG
    if ( !BN_rand_range(m_bn.get(),max.m_bn.get()))
        throw std::range_error("error generating random number in range 0 - " + max.ToHex());
    return ToHex(); 
}


void BigNumber::seedRNG (const std::string& seed) {
    RAND_seed(seed.c_str(), (int)seed.size());
}

std::string BigNumber::generateRandHexWithSeed(const std::string& seed, const int& nsize){
    RAND_seed(seed.c_str(), (int)seed.size());
    return generateRandHex(nsize);
}

std::string BigNumber::generateRandDecWithSeed(const std::string& seed, const int& nsize){
    RAND_seed(seed.c_str(), (int)seed.size());   
    return generateRandDec (nsize);
}

std::string BigNumber::generateNegRandHexWithSeed (const std::string& seed, const int& nsize){
    RAND_seed(seed.c_str(), (int)seed.size());      
    return generateNegRandHex(nsize);
}

std::string BigNumber::generateNegRandDecWithSeed (const std::string& seed, const int& nsize){
    RAND_seed(seed.c_str(), (int)seed.size());   
    return generateNegRandDec(nsize);
}

std::string BigNumber::generateRangRandHexWithSeed (const std::string& seed, const BigNumber& upperLimit){
    RAND_seed(seed.c_str(), (int)seed.size());   
    generateRandRange(upperLimit);
    return ToHex(); 
}

std::string BigNumber::generateRangRandDecWithSeed (const std::string& seed, const BigNumber& upperLimit){
    RAND_seed(seed.c_str(), (int)seed.size());   
    generateRandRange(upperLimit);
    return ToHex(); 
}

// Generate random prime & return string Representation
std::string BigNumber::generateRandPrimeHex(const int& nsize)
{
    if (!BN_generate_prime_ex(m_bn.get(), nsize, 0, nullptr, nullptr, nullptr))
        throw std::runtime_error("error generating prime number");
    return ToHex();
}

std::string BigNumber::generateRandPrimeDec(const int& nsize)
{
    if (!BN_generate_prime_ex(m_bn.get(), nsize, 0, nullptr, nullptr, nullptr))
        throw std::runtime_error("error generating prime number");
    return ToDec();
}

std::string BigNumber::generateRandPrimeHexWithSeed(const std::string& seed, const int& nsize){
    if (!BN_generate_prime_ex(m_bn.get(), nsize, 0, nullptr, nullptr, nullptr))
        throw std::runtime_error("error generating prime number");
    return generateRandPrimeHex(nsize);
}

std::string BigNumber::generateRandPrimeDecWithSeed(const std::string& seed, const int& nsize){
    RAND_seed(seed.c_str(), (int)seed.size());
    return generateRandPrimeDec(nsize);
}

bool BigNumber::isPrime() const{
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    //int BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb);
    //const bool res = (bool) BN_is_prime_ex(m_bn.get(), BN_prime_checks, ctxptr.get(), nullptr);
    const bool res = (bool) BN_check_prime(m_bn.get(), ctxptr.get(), nullptr); 
    return res;
}


// friend free functions
BigNumber operator+ (const BigNumber& obj1, const BigNumber& obj2) {
    BigNumber res ; 
    if (!BN_add(res.m_bn.get(),obj1.m_bn.get(),obj2.m_bn.get()))
        throw std::runtime_error("error");

    return res; 
}

BigNumber operator+ ( const BigNumber& obj1, const int& nVal){
    // does this work for negative numbers?
    BigNumber obj2; 
    std::stringstream numStr ; 
    numStr << nVal ; 
    obj2.FromDec (numStr.str());
    BigNumber res; 
    if (!BN_add(res.m_bn.get(),obj1.m_bn.get(),obj2.m_bn.get()))
        throw std::runtime_error("error");
    return res;
}


BigNumber operator- (const BigNumber& obj1, const BigNumber& obj2){
    BigNumber res; 
    if (!BN_sub(res.m_bn.get(), obj1.m_bn.get(), obj2.m_bn.get()))
        throw std::runtime_error("error");
    return res;
}

BigNumber operator- (const BigNumber& obj1, const int& val){
     // does this work for negative numbers?
    BigNumber obj2; 
    std::stringstream numStr ; 
    numStr << val ; 
    obj2.FromDec (numStr.str());
    BigNumber res; 
    if (!BN_sub(res.m_bn.get(), obj1.m_bn.get(), obj2.m_bn.get()))
        throw std::runtime_error("error");
    return res; 
}

BigNumber operator* (const BigNumber& obj1, const BigNumber& obj2){
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    BigNumber bnMul; 
    if (!BN_mul(bnMul.m_bn.get(), obj1.m_bn.get(), obj2.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error");
    return bnMul; 
}


BigNumber operator/ (const BigNumber& obj1, const BigNumber& obj2)
{
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    if (obj2.ToDec() == "0"){
        throw  std::runtime_error("Divide by zero exception");
    }
    
    BigNumber bnDiv; 
    if (!BN_div(bnDiv.m_bn.get(), NULL, obj1.m_bn.get(), obj2.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error");
    return bnDiv; 
}

BigNumber operator% (const BigNumber& obj1, const BigNumber& obj2){
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    BigNumber bnMod;
    if (!BN_mod(bnMod.m_bn.get(), obj1.m_bn.get(), obj2.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error");
    return bnMod; 
}

//BN_cmp() returns -1 if a < b, 0 if a==b, 1 if a > b
bool operator> (const BigNumber& obj1, const BigNumber& obj2){
    if (BN_cmp(obj1.m_bn.get(), obj2.m_bn.get()) == 1 ){
        return true;
    }else{return false;}
}

bool operator< (const BigNumber& obj1, const BigNumber& obj2){
    if (BN_cmp(obj1.m_bn.get(), obj2.m_bn.get()) == -1 ){
        return true;
    }else{return false;}
}

bool operator== (const BigNumber& obj1,  const BigNumber& obj2){
    if (BN_cmp(obj1.m_bn.get(), obj2.m_bn.get()) == 0 ){
        return true;
    }else{return false;} 
}

BigNumber operator>> (const BigNumber& obj1, const BigNumber& obj2)
{
    if (obj2.ToDec().length() > 0 && obj2.ToDec()[0] == '-')
    {
        throw  std::runtime_error("negative shift count");
    }

    BigNumber _obj2 = obj2, _obj1 = obj1; 
    BigNumber intValBn; 
    const int intVal = 2147483647;
    std::stringstream numStr ; 
    numStr << intVal ; 
    intValBn.FromDec(numStr.str());

    while(_obj2 > intValBn)
    {
        _obj2 = _obj2 - intValBn;   
        _obj1 = _obj1 >> intVal;

    }

    _obj1 = _obj1 >> std::stoi(_obj2.ToDec());
    return _obj1;
}

BigNumber operator>> (const BigNumber& obj, const int& val){

    if (val < 0){
        throw  std::runtime_error("negative shift count");
    }

    BigNumber res; 
    if(!BN_rshift(res.m_bn.get(), obj.m_bn.get(), val))
        throw std::runtime_error("Unable to right-shift by " + std::to_string(val));
    return res; 
}

BigNumber operator<< (const BigNumber& obj1, const BigNumber& obj2)
{
    if (obj2.ToDec().length() > 0 && obj2.ToDec()[0] == '-')
    {
        throw  std::runtime_error("negative shift count");
    }

    BigNumber _obj2 = obj2, _obj1 = obj1; 
    BigNumber intValBn; 
    const int intVal = 2147483647;
    std::stringstream numStr ; 
    numStr << intVal; 
    intValBn.FromDec(numStr.str());

    while(_obj2 > intValBn)
    {
        _obj2 = _obj2 - intValBn;   
        _obj1 = _obj1 << intVal;
    }
    _obj1 = _obj1 << std::stoi(_obj2.ToDec());
    return _obj1;

}

BigNumber operator<< (const BigNumber& obj, const int& val){
    if (val < 0){
        throw  std::runtime_error("negative shift count");
    }
    BigNumber res; 
     if(!BN_lshift(res.m_bn.get(), obj.m_bn.get(), val))
        throw std::runtime_error("Unable to left-shift by " + std::to_string(val));
    return res; 
}


BigNumber Inv_mod (const BigNumber& crARG, const BigNumber& crMOD){
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    BigNumber res;
    if (!BN_mod_inverse(res.m_bn.get(), crARG.m_bn.get(), crMOD.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error mod inverse");
    return res;
}

BigNumber Add_mod (const BigNumber& crLHS, const BigNumber& crRHS, const BigNumber& crMOD){
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    BigNumber res;
    if (!BN_mod_add(res.m_bn.get(), crLHS.m_bn.get(), crRHS.m_bn.get(), crMOD.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error mod add");
    return res; 
}

BigNumber Sub_mod (const BigNumber& crLHS, const BigNumber& crRHS, const BigNumber& crMOD){
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    BigNumber res;
    if (!BN_mod_sub(res.m_bn.get(), crLHS.m_bn.get(), crRHS.m_bn.get(), crMOD.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error mod sub");

    return res; 
}

BigNumber Mul_mod (const BigNumber& crLHS, const BigNumber& crRHS, const BigNumber& crMOD){
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    BigNumber res;
    if (!BN_mod_mul(res.m_bn.get(), crLHS.m_bn.get(), crRHS.m_bn.get(), crMOD.m_bn.get(), ctxptr.get()))
        throw std::runtime_error("error mod mul");
    return res;
}

BigNumber Div_mod (const BigNumber& crLHS, const BigNumber& crRHS, const BigNumber& crMOD){
    BigNumber invRHS = Inv_mod(crRHS, crMOD);
    BigNumber resDiv = Mul_mod(crLHS, invRHS, crMOD);
    return resDiv;
}

// free functions
BigNumber GenerateRand (const int& size ){
    BigNumber res ;
    res.generateRandHex (size) ;
    return res ; 
}

BigNumber GenerateRandNegative (const int& size){
    BigNumber res ; 
    res.generateNegRandHex (size);
    return res; 
}

BigNumber GenerateOne (){
    BigNumber bn; 
    bn.One(); 
    return bn; 
}

BigNumber GenerateZero(){
    BigNumber bn; 
    bn.Zero (); 
    return bn;
}

BigNumber GenerateRandRange(const BigNumber& min, const BigNumber& max ,const int& nsize){
    // please note that negative ranges are allowed.
    BigNumber Range = max - min + 1; 
    BigNumber RandomRange;     
    RandomRange.generateRandRange(Range);
    BigNumber Val = min + (RandomRange % Range);
    if (Val < min || Val > max)
        throw std::out_of_range("RANGE VIOLATION MIN VALUE" + min.ToDec() + "\t MAX VALUE " + max.ToDec());
    return Val;
}

BigNumber GenerateRandPrime(const int& size){
    BigNumber res;
    res.generateRandPrimeHex(size);
    return res;
}

