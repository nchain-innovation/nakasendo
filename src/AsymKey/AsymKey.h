#ifndef __ASYMKEY_H__
#define __ASYMKEY_H__

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

class AsymKeyImpl; 
//class KeyShare; 
class BigNumber;
class ECPoint; 

using pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

// Template function for hashing messages with a configurable hash function
template <const EVP_MD* (*HashFunc)() = EVP_sha256>
std::unique_ptr<unsigned char[]> hash_msg(const std::string& input_msg, size_t& len);

class AsymKey
{
    public:
        explicit AsymKey();
        explicit AsymKey(const int& groupNID);
        explicit AsymKey(const pkey_ptr&); 
        ~AsymKey() = default; 

        //moveable
        AsymKey(AsymKey&& obj);
        AsymKey& operator=(AsymKey&& obj);


        bool is_valid() const; // Check if the keys satisfy pubkey = privkey * G

        //// some usefull infomation about the EC group
        int GroupNid() const;
        ECPoint Group_G() const;
        BigNumber Group_p() const;
        BigNumber Group_a() const; 
        BigNumber Group_b() const;
        BigNumber Group_Order() const;
 
        

        ECPoint exportPublicKey() const;
        BigNumber exportPrivateKey() const; 

        std::string exportPublicKeyPEM() const; 
        std::string exportPrivateKeyPEM() const; 

        //void importPrivateKeyPEM(const std::string&);
        //void importPrivateKey(const BigNumber&);


        //std::string exportPrivateHEX() const;
        //std::string exportPublicPEM()  const;
        //std::string exportPrivatePEM() const;
        //std::string exportPrivatePEMEncrypted( const std::string& ) const ;
        //void importPrivatePEMEncrypted( const std::string&, const std::string& ) ;
        //void importPrivatePEM(const std::string&);// Import PEM private key
        //void importPrivateHEX(const std::string&);// Import HEX private key, knowing it is the right group
        //void importPrivateBN(const BigNumber&); 
#if 0 
        std::string exportSharedSecretHex(const std::string& crOtherPublicPEMKey) const;// Calculate the shared secrete giving the public key from other

        AsymKey derive(const std::string& crAdditiveMsg) const;
#endif
        /// Sign the message, return <r,s>  component
        // This sign function performs a hash on the input
        std::pair<BigNumber, BigNumber> sign(const std::string& crMsg) const;
        // this sign function DOES NOT perform a hash on the input (a ssumed pre-hashed)
        std::pair<BigNumber, BigNumber> sign_S256_str(const std::string&) const;
        // this sign function DOES NOT perform a hash on the input  (assumed pre-hashed)
        std::pair<BigNumber, BigNumber> sign_S256_bytes(const std::unique_ptr<unsigned char[]>&, const size_t&) const;
#if 0 
        /// Sign the message, return <r,s>  component with the provided inv_k and r
        std::pair<std::string, std::string> sign_ex(const std::string& crMsg, const std::string& inv_k_hex, const std::string& r_hex) const;
        //This sign function takes an std::string whose contents are hex representation of a SHA-256 of some input
        std::pair<std::string, std::string> signS256(const std::string& crMsg) const;
        //This sign function takes a std::unique_ptr<unsigned char> whose contents are the raw bytes of a SHA-256 of some input
        std::pair<std::string, std::string> sign256Raw(const std::unique_ptr<unsigned char[]>&, const unsigned int&) const ;
        // split the key into multiple parts
        //std::vector<KeyShare> split (const int&, const int&);
        // recover a key from multiple shares
        //void recover (const std::vector<KeyShare>& ); 
#endif

    private:
        pkey_ptr m_key;

        //copyable (deactivate copy and assignment for this class)
        AsymKey(const AsymKey& obj);
        AsymKey& operator=(const AsymKey& obj);
};


AsymKey FromPemStr(const std::string&);
AsymKey FromBigNumber(const BigNumber&, const int& curveID=714); // defaulted to secp256k1

ECPoint pubkey_pem2hex(const std::string& crPubPEMkey);

bool verify(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::pair<BigNumber, BigNumber>& rs);
bool verify_S256_str(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::pair<BigNumber, BigNumber>& rs);
bool verifyDER_S256_str(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::unique_ptr<unsigned char[]>&, const size_t&);
bool verify_S256_bytes(const std::unique_ptr<unsigned char[]>& crMsg, const size_t& crMsgLen, const std::string& crPublicKeyPEMStr, const std::pair<BigNumber, BigNumber>& rs);
std::unique_ptr<unsigned char[]> DEREncodedSignature(const BigNumber&, const BigNumber&, size_t& len);
#if 0 
AsymKey_API bool verify(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::pair<std::string, std::string>& rs, const int& );
AsymKey_API bool verifyDER(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::unique_ptr<unsigned char[]>&, const size_t&, const int&);

AsymKey_API bool verifyWithHashDigest(const std::unique_ptr<unsigned char[]>& crMsg, const unsigned int& crMsgLen, const std::string& crPublicKeyPEMStr, const std::pair<std::string, std::string>& rs, const int&);
AsymKey_API bool verifyDERWithHashDigest(const std::unique_ptr<unsigned char[]>& crMsg, const unsigned int& crMsgLen, const std::string& crPublicKeyPEMStr, const std::unique_ptr<unsigned char[]>&, const size_t&, const int&);

AsymKey_API bool verifyHashS256String(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::pair<std::string, std::string>& rs, const int& nid=714);
AsymKey_API bool verifyDERHashS256String(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::unique_ptr<unsigned char[]>&, const size_t&, const int&);


AsymKey_API std::string derive_pubkey(const std::string& crPubPEMkey, const std::string& crRandomMsg);
AsymKey_API std::pair<std::string, std::string> pubkey_pem2hex(const std::string& crPubPEMkey);
AsymKey_API std::string pubkey_pem2Hex_point(const std::string& crPubPEMkey, const bool& compressed=true);
AsymKey_API std::string pubkey_coordinates2pem(const std::string&, const std::string&, const int nid = 714);


#endif
#endif //#ifndef __ASYMKEY_H__
