#include <AsymKey/AsymKey.h>
#include <BigNumbers/BigNumbers.h>
#include <Polynomial/Polynomial.h>
#include <ECPoint/ECPoint.h>
#include <Utils/hashing.h>
#include <SecretShare/KeyShare.h>
#include <SecretShare/SecretSplit.h>

#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for 
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>
#include <assert.h> 


using SIG_ptr = std::unique_ptr< ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
using BIO_ptr = std::unique_ptr< BIO, decltype(&BIO_free_all)  >;
using BN_CTX_ptr = std::unique_ptr< BN_CTX, decltype(&BN_CTX_free) >;
using EC_GROUP_ptr = std::unique_ptr< EC_GROUP, decltype(&EC_GROUP_free) >;
using EC_POINT_ptr = std::unique_ptr< EC_POINT, decltype(&EC_POINT_free) >;
using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using OSSL_PARAM_BLD_ptr = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

inline void help_openssl_free_char(char* p) { OPENSSL_free(p); }
inline void help_openssl_free_uchar(unsigned char* p) { OPENSSL_free(p); }

//using STR_ptr = std::unique_ptr<char, decltype(&help_openssl_free_char)>;//
using SSL_UCharPtr = std::unique_ptr<unsigned char, decltype(&help_openssl_free_uchar)>;

AsymKey::AsymKey(): m_key(nullptr, EVP_PKEY_free){
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    if(!pkey_ctx)
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for EC");
    
    if (EVP_PKEY_keygen_init(pkey_ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_group_name(pkey_ctx.get(), OBJ_nid2sn(NID_secp256k1)) <= 0) {
            throw std::runtime_error("Failed to initialize EC key generation");
    }
    EVP_PKEY* temp_key = nullptr;
    if (EVP_PKEY_generate(pkey_ctx.get(), &temp_key) <= 0)
        throw std::runtime_error("Failed to generate EC key");
    
    m_key.reset(temp_key);
    if (!EVP_PKEY_is_a(m_key.get(), "EC"))
        throw std::runtime_error("Generated key is not EC!");
}

AsymKey::AsymKey(const int& groupNID) : m_key(nullptr, EVP_PKEY_free) {
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    if(!pkey_ctx)
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for EC");
    
    if (EVP_PKEY_keygen_init(pkey_ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_group_name(pkey_ctx.get(), OBJ_nid2sn(groupNID)) <= 0) {
            throw std::runtime_error("Failed to initialize EC key generation");
    }
    EVP_PKEY* temp_key = nullptr;
    if (EVP_PKEY_generate(pkey_ctx.get(), &temp_key) <= 0)
        throw std::runtime_error("Failed to generate EC key");
    
    m_key.reset(temp_key);
    if (!EVP_PKEY_is_a(m_key.get(), "EC"))
        throw std::runtime_error("Generated key is not EC!");
}

AsymKey::AsymKey(const pkey_ptr& key) : m_key(nullptr, EVP_PKEY_free){
    m_key.reset(EVP_PKEY_dup(key.get()));
    return;
}

AsymKey::AsymKey(AsymKey&& other) 
        : m_key(std::move(other.m_key)){ 
    return;
}

AsymKey& AsymKey::operator=(AsymKey&& other) {
    if (this != &other) {  // Self-assignment check
        m_key = std::move(other.m_key);
    }
    return *this;
}


bool AsymKey::is_valid() const {
    if(!m_key)
        return false; 
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new(m_key.get(), nullptr), EVP_PKEY_CTX_free);
    if(!pkey_ctx)
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for EC");
    
    // Check key parameters (e.g., valid EC curve, domain parameters)
    if (EVP_PKEY_param_check(pkey_ctx.get()) != 1){
        std::cerr << "EVP_PKEY_param_check failed" << std::endl;
        return false;
    }

    // Check public key validity
    if (EVP_PKEY_public_check(pkey_ctx.get()) != 1) {
        std::cerr << "EVP_PKEY_public_check failed" << std::endl;
        return false;
    }

    if (EVP_PKEY_private_check(pkey_ctx.get()) != 1) {
        std::cerr << "EVP_PKEY_private_check failed" << std::endl;
        return false;
    }

    if (!EVP_PKEY_is_a(m_key.get(), "EC"))
        throw std::runtime_error("Generated key is not EC!");
    return true;
}

int AsymKey::GroupNid() const {
    char curve_name[64];
    size_t len=0; 
    if (!EVP_PKEY_get_utf8_string_param(m_key.get(), OSSL_PKEY_PARAM_GROUP_NAME,
        curve_name, sizeof(curve_name), &len)) {
        std::cout << "Group name call failed" << std::endl;
    }

    int nid = OBJ_txt2nid(curve_name); 
    if (nid == NID_undef)
        throw std::runtime_error("Failed to convert group name to NID for CURVE");
    
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free); 
    return EC_GROUP_get_curve_name(gp.get());
}


ECPoint AsymKey::Group_G() const {
    char curve_name[64];
    size_t len=0; 
    if (!EVP_PKEY_get_utf8_string_param(m_key.get(), OSSL_PKEY_PARAM_GROUP_NAME,
        curve_name, sizeof(curve_name), &len)) {
        throw std::runtime_error("Group name call failed in Group_G()");
    }
    int nid = OBJ_txt2nid(curve_name); 
    if (nid == NID_undef)
        throw std::runtime_error("Failed to convert group name to NID for CURVE");
    
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free); 
    const EC_POINT * tmp_pt = EC_GROUP_get0_generator(gp.get()); 
    EC_POINT_ptr ec(EC_POINT_new(gp.get()), &EC_POINT_free);
    if(!EC_POINT_copy(ec.get(),tmp_pt))
        throw std::runtime_error("failed tp getECGroup generator point");

    ECPoint res(gp, ec, nid); 
    return res; 
}

BigNumber AsymKey::Group_p() const{
    BigNumber res;
    BIGNUM * p_bn = res.bn_ptr().get () ; 
    if (!EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_EC_P, &p_bn)) {
        std::cerr << "Failed to get EC 'p' parameter" << std::endl;
        throw std::runtime_error("Failed to get EC 'p' parameter");
    }
    return res; 
} 

BigNumber AsymKey::Group_a() const{
    BigNumber res;
    BIGNUM * p_bn = res.bn_ptr().get () ; 
    if (!EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_EC_A, &p_bn)) {
        throw std::runtime_error("Failed to get EC 'a' parameter");
    }
    return res; 
}
BigNumber AsymKey::Group_b() const{
    BigNumber res;
    BIGNUM * p_bn = res.bn_ptr().get () ; 
    if (!EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_EC_B, &p_bn)) {
        throw std::runtime_error("Failed to get EC 'b' parameter");
    }
    return res; 
}
BigNumber AsymKey::Group_Order() const{
    BigNumber res;
    BIGNUM * p_bn = res.bn_ptr().get () ; 
    if (!EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_EC_ORDER, &p_bn)) {
        throw std::runtime_error("Failed to get EC 'ORDER' parameter");
    }
    return res; 
}

ECPoint AsymKey::exportPublicKey() const {
    char curve_name[64];
    size_t len=0; 
    if (!EVP_PKEY_get_utf8_string_param(
            m_key.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve_name, sizeof(curve_name), &len)
        ){
            throw std::runtime_error("Group name call failed");
    }

    int nid = OBJ_txt2nid(curve_name); 
    if (nid == NID_undef)
        throw std::runtime_error("Failed to convert group name to NID for CURVE");
    
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free); 
    BigNumber pub_x; 
    BigNumber pub_y; 

    BIGNUM* pub_rawptr_x = pub_x.bn_ptr().get();
    BIGNUM* pub_rawptr_y = pub_y.bn_ptr().get(); 

    if (!EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_EC_PUB_X, &pub_rawptr_x) ||
        !EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &pub_rawptr_y)) {
        throw std::runtime_error("Failed to extract public key components");
    }

    ECPoint res(nid); 
    res.SetAffineCoords(std::make_pair(pub_x, pub_y));
    return res; 
}

BigNumber AsymKey::exportPrivateKey() const {
    BigNumber res; 
    BIGNUM* raw_ptr = res.bn_ptr().get(); 
    if (EVP_PKEY_get_bn_param(m_key.get(), OSSL_PKEY_PARAM_PRIV_KEY, &raw_ptr) != 1) {
        throw std::runtime_error("Failed to extracct private key"); 
    }
    return res; 
}

std::string AsymKey::exportPublicKeyPEM() const{
    BIO_ptr outbio (BIO_new(BIO_s_mem()),&BIO_free_all);

    if (!PEM_write_bio_PUBKEY(outbio.get(), m_key.get()))
        throw std::runtime_error("Error writting public key");
    
    const int pubKeyLen = BIO_pending(outbio.get());
    std::string pubkey_str(pubKeyLen, '0');
    BIO_read(outbio.get(), (void*)&(pubkey_str.front()), pubKeyLen);

    return pubkey_str;
}

std::string AsymKey::exportPrivateKeyPEM() const{
    BIO_ptr outbio (BIO_new(BIO_s_mem()),&BIO_free_all);

    if (!PEM_write_bio_PrivateKey(outbio.get(), m_key.get(), NULL, NULL, 0, NULL, NULL))
        throw std::runtime_error("Error writting Private key");
    
    const int privKeyLen = BIO_pending(outbio.get());
    std::string privkey_str(privKeyLen, '0');
    BIO_read(outbio.get(), (void*)&(privkey_str.front()), privKeyLen);

    return privkey_str;
}

// hashes the imput
std::pair<BigNumber, BigNumber> AsymKey::sign(const std::string& input_msg) const{

    std::unique_ptr<unsigned char []> msg (new unsigned char[input_msg.size()]);
    int index(0);
    for(std::string::const_iterator iter = input_msg.begin(); iter != input_msg.end(); ++ iter){
        msg[index++] = *iter;
    }

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free); 
    if (!ctx) 
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    // Initialize signing operation
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, m_key.get()) != 1)
        throw std::runtime_error("EVP_DigestSignInit failed");

    // Update with message data
    if (EVP_DigestSignUpdate(ctx.get(), msg.get(), input_msg.size()) != 1)
        throw std::runtime_error("EVP_DigestSignUpdate failed");

    // Get required signature size
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1)
        throw std::runtime_error("EVP_DigestSignFinal failed to get signature size");

    // Finalize signing and get the signature
    std::unique_ptr<unsigned char[]> digest(new unsigned char[sig_len]);
    if (EVP_DigestSignFinal(ctx.get(), digest.get(), &sig_len) != 1)
        throw std::runtime_error("EVP_DigestSignFinal failed to get signature data");
#if 0
     std::cout << "size of the signature (sig_len) -> " << sig_len << std::endl;
     std::cout << "Signature (DER-encoded): ";
     for (size_t i = 0; i < sig_len; i++) {
         printf("%02X", digest[i]);
     }
     std::cout << std::endl;
#endif
    const unsigned char* p = digest.get();
    // Decode the DER signature into an ECDSA_SIG structure
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, sig_len);
    if (!sig)
        throw std::runtime_error("Failed to decode DER-encoded ECDSA signature"); 

    // Extract r and s
    const BIGNUM* r_raw = nullptr;
    const BIGNUM* s_raw = nullptr;
    ECDSA_SIG_get0(sig, &r_raw, &s_raw);
    BigNumber r_ptr ; 
    BigNumber s_ptr; 
    r_ptr.bn_ptr().reset(BN_dup(r_raw)); 
    s_ptr.bn_ptr().reset(BN_dup(s_raw)); 
    return {r_ptr, s_ptr};  // Return r and s

}

std::pair<BigNumber, BigNumber> AsymKey::sign_S256_str(const std::string& inputHash) const{
    size_t sig_len = 0;

    size_t digest_len= 0; 
    std::unique_ptr<unsigned char []> msg  = S256HashMsgToChar(inputHash,digest_len); 
    if(digest_len != SHA256_DIGEST_LENGTH)
        throw std::runtime_error("Invalid message length for SHA256 signing");

    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new(m_key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx) 
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    // Initialize signing (raw mode, no hashing)
    if (EVP_PKEY_sign_init(pkey_ctx.get()) != 1)
        throw std::runtime_error("EVP_PKEY_sign_init failed");
    
    // Determine signature length
    if (EVP_PKEY_sign(pkey_ctx.get(), nullptr, &sig_len, msg.get(), digest_len) != 1)
        throw std::runtime_error("EVP_PKEY_sign (size determination) failed");

    std::unique_ptr<unsigned char[]> sig(new unsigned char[sig_len]);
    // Perform the actual signing
    if (EVP_PKEY_sign(pkey_ctx.get(), sig.get(), &sig_len, msg.get(), digest_len) != 1)
        throw std::runtime_error("EVP_PKEY_sign failed");

    const unsigned char* p = sig.get();
    // Decode the DER signature into an ECDSA_SIG structure
    ECDSA_SIG* sig_rs = d2i_ECDSA_SIG(nullptr, &p, sig_len);
    if (!sig_rs)
        throw std::runtime_error("Failed to decode DER-encoded ECDSA signature"); 

#if 1
        std::cout << "size of the signature (sig_len) -> " << sig_len << std::endl;
        std::cout << "Signature (DER-encoded): ";
        for (size_t i = 0; i < sig_len; i++) {
            printf("%02X", sig[i]);
        }
        std::cout << std::endl;
#endif
    // Extract r and s
    const BIGNUM* r_raw = nullptr;
    const BIGNUM* s_raw = nullptr;
    ECDSA_SIG_get0(sig_rs, &r_raw, &s_raw);
    BigNumber r_ptr ; 
    BigNumber s_ptr; 
    r_ptr.bn_ptr().reset(BN_dup(r_raw)); 
    s_ptr.bn_ptr().reset(BN_dup(s_raw)); 
    return {r_ptr, s_ptr};  // Return r and s
}

std::pair<BigNumber, BigNumber> AsymKey::sign_S256_bytes(const std::unique_ptr<unsigned char[]>& msg, const size_t& msg_len) const{
    if(msg_len != SHA256_DIGEST_LENGTH)
        throw std::runtime_error("Invalid message length for SHA256 signing");
    
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new(m_key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx) 
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    size_t sig_len = 0;
    if (EVP_PKEY_sign_init(pkey_ctx.get()) != 1)
        throw std::runtime_error("EVP_PKEY_sign_init failed");
    
    // Determine signature length
    if (EVP_PKEY_sign(pkey_ctx.get(), nullptr, &sig_len, msg.get(), msg_len) != 1)
        throw std::runtime_error("EVP_PKEY_sign (size determination) failed");

    std::unique_ptr<unsigned char[]> sig(new unsigned char[sig_len]);
    // Perform the actual signing
    if (EVP_PKEY_sign(pkey_ctx.get(), sig.get(), &sig_len, msg.get(), msg_len) != 1)
        throw std::runtime_error("EVP_PKEY_sign failed");

    const unsigned char* p = sig.get();
    // Decode the DER signature into an ECDSA_SIG structure
    ECDSA_SIG* sig_rs = d2i_ECDSA_SIG(nullptr, &p, sig_len);
    if (!sig_rs)
        throw std::runtime_error("Failed to decode DER-encoded ECDSA signature"); 

#if 0
        std::cout << "size of the signature (sig_len) -> " << sig_len << std::endl;
        std::cout << "Signature (DER-encoded): ";
        for (size_t i = 0; i < sig_len; i++) {
            printf("%02X", sig[i]);
        }
        std::cout << std::endl;
#endif
    // Extract r and s
    const BIGNUM* r_raw = nullptr;
    const BIGNUM* s_raw = nullptr;
    ECDSA_SIG_get0(sig_rs, &r_raw, &s_raw);
    BigNumber r_ptr ; 
    BigNumber s_ptr; 
    r_ptr.bn_ptr().reset(BN_dup(r_raw)); 
    s_ptr.bn_ptr().reset(BN_dup(s_raw)); 
    return {r_ptr, s_ptr};  // Return r and s
}
// free functions
AsymKey FromPemStr(const std::string& crPEMStr){
    BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(bio.get(), static_cast<const char*>(crPEMStr.c_str()), (int)crPEMStr.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM string");

    pkey_ptr pkey ( PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL), EVP_PKEY_free); 
    if(!pkey)
        throw std::runtime_error("Error reading private key"); 

    if (!EVP_PKEY_is_a(pkey.get(), "EC"))
        throw std::runtime_error("Generated key is not EC!");

    AsymKey tmpkey(pkey);
    return std::move(AsymKey(pkey));
}

AsymKey FromBigNumber(const BigNumber& bn_priv, const int& curveID){
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    if(!pkey_ctx)
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for EC");


    // Convert NID to curve name (e.g., "secp256k1")
    const char* curve_name = OBJ_nid2sn(curveID);
    if (!curve_name) {
        std::cerr << "Invalid curve NID" << std::endl;
        throw std::runtime_error("nvalid curve NID"); 
    }

    size_t bn_size = BN_num_bytes(bn_priv.bn_ptr().get());

    std::vector<u_int8_t> priv_key = bn_priv.ToBin(); 
    // this reverse is required as when creating a key from bytes, openssl3 expects
    // the bytes in little-endian format (that's how EVP_PKEY is represented internally)
    std::reverse(priv_key.begin(), priv_key.end());

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)curve_name, 0),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, priv_key.data(), bn_size),
        OSSL_PARAM_END
    };
    
    pkey_ptr pkey_ptr(EVP_PKEY_new(), EVP_PKEY_free); 
    EVP_PKEY* pkey = pkey_ptr.get();
    // Generate key from data
    if (EVP_PKEY_fromdata_init(pkey_ctx.get()) <= 0 || EVP_PKEY_fromdata(pkey_ctx.get(), &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        std::cerr << "Error: Failed to set EC Private Key using EVP_PKEY_fromdata()" << std::endl;
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error: Failed to set EC Private key"); 
    }
    return std::move(AsymKey(pkey_ptr)); 
}

ECPoint pubkey_pem2hex(const std::string& PubPEMkey){
    BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(bio.get(), static_cast<const char*>(PubPEMkey.c_str()), (int)PubPEMkey.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM string");

    // Read the PEM public key into EVP_PKEY
    pkey_ptr pkey (PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free); 
    if(!pkey)
        throw std::runtime_error("Error reading public key"); 

    BigNumber x_ptr; 
    BigNumber y_ptr; 

    BIGNUM* raw_x_ptr = x_ptr.bn_ptr().get(); 
    BIGNUM* raw_y_ptr = y_ptr.bn_ptr().get(); 

    if (!EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_EC_PUB_X, &raw_x_ptr) ||
        !EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &raw_y_ptr)){
        throw std::runtime_error("Failed to extract EC affine coordinates");
    }

    // Retrieve curve name
    char curve_name[80]; // Buffer for the curve name
    size_t name_len = 0;
    if (!EVP_PKEY_get_utf8_string_param(pkey.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve_name, sizeof(curve_name), &name_len))
        throw std::runtime_error("Failed to retrieve EC curve name");

    int nid = OBJ_txt2nid(curve_name); 
    if (nid == NID_undef)
        throw std::runtime_error("Failed to convert group name to NID for CURVE");


    ECPoint pubkey(x_ptr, y_ptr, nid); 
    return pubkey; 
}

bool verify(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::pair<BigNumber, BigNumber>& rs){

    SIG_ptr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
     // Set r and s inside ECDSA_SIG
     if (!ECDSA_SIG_set0(sig.get(), BN_dup(rs.first.bn_ptr().get()), BN_dup(rs.second.bn_ptr().get())))
        throw std::runtime_error("Failed to set r and s in ECDSA_SIG");

    // Get the DER encoding size
    int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_len <= 0)
        throw std::runtime_error("Failed to determine DER size");
    SSL_UCharPtr der_sig_ptr(new unsigned char[der_len], &help_openssl_free_uchar);
    unsigned char* der_sig_raw_ptr = der_sig_ptr.get();

    if (i2d_ECDSA_SIG(sig.get(), &der_sig_raw_ptr) <= 0)
        throw std::runtime_error("Failed to encode signature in DER format");


    BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(bio.get(), static_cast<const char*>(crPublicKeyPEMStr.c_str()), (int)crPublicKeyPEMStr.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM string");
    // Read the PEM public key into EVP_PKEY
    pkey_ptr pkey (PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free); 
    if(!pkey)
        throw std::runtime_error("Error reading public key"); 


    std::unique_ptr<unsigned char []> msg (new unsigned char[crMsg.size()]);
    int index(0);
    for(std::string::const_iterator iter = crMsg.begin(); iter != crMsg.end(); ++ iter){
        msg[index++] = *iter;
    }

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free); 
    if (!ctx.get()) 
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1)
        throw std::runtime_error("EVP_DigestVerifyInit failed");

    if (EVP_DigestVerifyUpdate(ctx.get(), msg.get(), crMsg.size()) != 1)
        throw std::runtime_error("EVP_DigestVerifyUpdate failed"); 

    if (EVP_DigestVerifyFinal(ctx.get(), der_sig_ptr.get(),der_len) == 1){
        //std::cout << "Signature verification successful\n";
        return true;
    } else {
        //std::cerr << "Signature verification failed\n";
        return false;
    }
}

bool verify_S256_str(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::pair<BigNumber, BigNumber>& rs){
    SIG_ptr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
     // Set r and s inside ECDSA_SIG
     if (!ECDSA_SIG_set0(sig.get(), BN_dup(rs.first.bn_ptr().get()), BN_dup(rs.second.bn_ptr().get())))
        throw std::runtime_error("Failed to set r and s in ECDSA_SIG");

    // Get the DER encoding size
    int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_len <= 0)
        throw std::runtime_error("Failed to determine DER size");
    SSL_UCharPtr der_sig_ptr(new unsigned char[der_len], &help_openssl_free_uchar);
    unsigned char* der_sig_raw_ptr = der_sig_ptr.get();

    if (i2d_ECDSA_SIG(sig.get(), &der_sig_raw_ptr) <= 0)
        throw std::runtime_error("Failed to encode signature in DER format");


    BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(bio.get(), static_cast<const char*>(crPublicKeyPEMStr.c_str()), (int)crPublicKeyPEMStr.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM string");
    // Read the PEM public key into EVP_PKEY
    pkey_ptr pkey (PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free); 
    if(!pkey)
        throw std::runtime_error("Error reading public key"); 


    size_t digest_len = 0; 
    std::unique_ptr<unsigned char []> msg = S256HashMsgToChar(crMsg, digest_len); 
    if(digest_len != SHA256_DIGEST_LENGTH)
        throw std::runtime_error("Hash digest size is not 32 bytes");

    // Create verification context
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx) 
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_PKEY_verify_init(pkey_ctx.get()) <= 0)
        throw std::runtime_error("EVP_PKEY_verify_init failed");

    // Set the digest algorithm explicitly to SHA-256
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_signature_md failed");

    // Perform raw verification (signature, precomputed SHA-256 hash)
    int verify_status = EVP_PKEY_verify(
        pkey_ctx.get(),
        der_sig_ptr.get(), der_len,  // DER-encoded signature
        msg.get(), SHA256_DIGEST_LENGTH  // Precomputed SHA-256 hash
    );

    if (verify_status == 1){
        std::cout << "Signature verification successful\n";
        return true;
    } else {
        std::cerr << "Signature verification failed\n";
        return false;
    }
}

bool verifyDER_S256_str(const std::string& crMsg, const std::string& crPublicKeyPEMStr, const std::unique_ptr<unsigned char[]>& der_sig, const size_t& der_len){
    size_t digest_len = 0; 
    std::unique_ptr<unsigned char []> msg = S256HashMsgToChar(crMsg, digest_len); 
    if(digest_len != SHA256_DIGEST_LENGTH)
        throw std::runtime_error("Hash digest size is not 32 bytes");

    BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(bio.get(), static_cast<const char*>(crPublicKeyPEMStr.c_str()), (int)crPublicKeyPEMStr.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM string");
    // Read the PEM public key into EVP_PKEY
    pkey_ptr pkey (PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free); 
    if(!pkey)
        throw std::runtime_error("Error reading public key"); 

    // Create verification context
    EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free);
    if (!pkey_ctx) 
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_PKEY_verify_init(pkey_ctx.get()) <= 0)
        throw std::runtime_error("EVP_PKEY_verify_init failed");

    // Set the digest algorithm explicitly to SHA-256
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_signature_md failed");

    // Perform raw verification (signature, precomputed SHA-256 hash)
    int verify_status = EVP_PKEY_verify(
        pkey_ctx.get(),
        der_sig.get(), der_len,  // DER-encoded signature
        msg.get(), SHA256_DIGEST_LENGTH  // Precomputed SHA-256 hash
    );

    if (verify_status == 1){
        std::cout << "Signature verification successful\n";
        return true;
    } else {
        std::cerr << "Signature verification failed\n";
        return false;
    }
}

bool verify_S256_bytes(const std::unique_ptr<unsigned char[]>& crMsg, const size_t& crMsgLen, const std::string& crPublicKeyPEMStr, const std::pair<BigNumber, BigNumber>& rs){
    if(crMsgLen != SHA256_DIGEST_LENGTH)
        throw std::runtime_error("Hash digest size is not 32 bytes");


    BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(bio.get(), static_cast<const char*>(crPublicKeyPEMStr.c_str()), (int)crPublicKeyPEMStr.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM string");
    // Read the PEM public key into EVP_PKEY
    pkey_ptr pkey (PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free); 
    if(!pkey)
        throw std::runtime_error("Error reading public key"); 
    
    SIG_ptr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
    // Set r and s inside ECDSA_SIG
    if (!ECDSA_SIG_set0(sig.get(), BN_dup(rs.first.bn_ptr().get()), BN_dup(rs.second.bn_ptr().get())))
        throw std::runtime_error("Failed to set r and s in ECDSA_SIG");

    // Get the DER encoding size
    int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_len <= 0)
        throw std::runtime_error("Failed to determine DER size");
    SSL_UCharPtr der_sig_ptr(new unsigned char[der_len], &help_openssl_free_uchar);
    unsigned char* der_sig_raw_ptr = der_sig_ptr.get();

    if (i2d_ECDSA_SIG(sig.get(), &der_sig_raw_ptr) <= 0)
        throw std::runtime_error("Failed to encode signature in DER format");
    
     // Create verification context
     EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free);
     if (!pkey_ctx) 
         throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_PKEY_verify_init(pkey_ctx.get()) <= 0)
        throw std::runtime_error("EVP_PKEY_verify_init failed");

    // Set the digest algorithm explicitly to SHA-256
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_signature_md failed");

    // Perform raw verification (signature, precomputed SHA-256 hash)
    int verify_status = EVP_PKEY_verify(
        pkey_ctx.get(),
        der_sig_ptr.get(), der_len,  // DER-encoded signature
        crMsg.get(), SHA256_DIGEST_LENGTH  // Precomputed SHA-256 hash
    );

    if(verify_status == 1){
        std::cout << "Signature verification successful\n";
        return true;
    }else{
        std::cerr << "Signature verification failed\n";
        return false;
    }
}

std::unique_ptr<unsigned char[]> DEREncodedSignature(const BigNumber& r, const BigNumber& s,  size_t& len){
    SIG_ptr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
     // Set r and s inside ECDSA_SIG
     if (!ECDSA_SIG_set0(sig.get(), BN_dup(r.bn_ptr().get()), BN_dup(s.bn_ptr().get())))
        throw std::runtime_error("Failed to set r and s in ECDSA_SIG");

    // Get the DER encoding size
    int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_len <= 0)
        throw std::runtime_error("Failed to determine DER size");
    std::unique_ptr<unsigned char[]> der_sig_ptr(new unsigned char[der_len]);
    unsigned char* der_sig_raw_ptr = der_sig_ptr.get();

    if (i2d_ECDSA_SIG(sig.get(), &der_sig_raw_ptr) <= 0)
        throw std::runtime_error("Failed to encode signature in DER format");
    
    len = der_len;
    return std::move(der_sig_ptr);
}

std::vector<KeyShare> split (const AsymKey& key, const int& threshold, const int& maxshares){
    BigNumber number = key.exportPrivateKey();
    BigNumber mod = key. Group_Order();
    int degree = threshold-1;
    Polynomial poly(degree, mod, number);
    std::vector<KeyShare> shares = make_shared_secret (poly, threshold, maxshares);
    return shares; 
}
AsymKey recover (const std::vector<KeyShare>& ks, const int& groupID){
    BigNumber mod; 
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(groupID), &EC_GROUP_free); 
    //BIGNUM_ptr mod_ptr(EC_GROUP_get0_order(gp.get())); 
    const BIGNUM *order = EC_GROUP_get0_order(gp.get());
    mod.bn_ptr().reset(BN_dup(order)); 
    //mod_ptr = EC_GROUP_get0_order(gp.get());
    std::cout << mod.ToHex() << std::endl; 
    BigNumber secret; 
    secret.Zero(); 
    try{
        secret = RecoverSecret(ks, mod); 
    }
    catch(std::exception& err){
        throw;
    }

    std::cout << "recovered secret -> " << secret.ToHex() << std::endl;
    AsymKey key = FromBigNumber(secret, groupID);
    std::cout << "recovered key recover function -> " << key.exportPrivateKey().ToHex() << std::endl; 
    //return FromBigNumber(secret, groupID);
    return key; 
}

// Explicitly instantiate the template for EVP_sha256 (or other hash functions)
//template std::unique_ptr<unsigned char[]> hash_msg<EVP_sha256>(const std::string& input_msg, size_t& len);


