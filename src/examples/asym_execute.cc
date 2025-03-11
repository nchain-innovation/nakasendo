#include <iostream>
#include <set>
#include <vector>
#include <AsymKey/AsymKey.h>
#include <ECPoint/ECPoint.h>
#include <Utils/conversions.h>
#include <SecretShare/KeyShare.h>
#include <SecretShare/SecretSplit.h>

#include <Utils/hashing.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <cassert>

int main(int argc, char* argv[]){
    std::cout << "starting" << std::endl; 
    OPENSSL_init_crypto(0, NULL);
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy"); // Needed for some EC curves
#if 0 
    AsymKey key;

    assert(key.is_valid());


    const int test_groupID = key.GroupNid();
    std::cout << test_groupID << std::endl; 

    std::cout << key.Group_G().ToHex() << std::endl; 
    //key.Group_p (); 
    std::cout << key.Group_p().ToHex() << std::endl; 

    // test curves 
    const auto nb_curves = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve *curve_list = (EC_builtin_curve *)OPENSSL_malloc(sizeof(EC_builtin_curve) * nb_curves);
    const auto nb_curves_r = EC_get_builtin_curves(curve_list, nb_curves);

    //EXPECT_EQ(nb_curves_r, nb_curves);

    size_t i{0};
    while (i < nb_curves)
    {
        const int curve_groupNID = curve_list[i].nid;
       // std::cout << "Test curve -> " << curve_groupNID << std::endl; 
        if (curve_groupNID != 749 && curve_groupNID != 750){
            AsymKey key(curve_groupNID);
        }
        ++i;
    }

    OPENSSL_free(curve_list);


    const std::string test_pubkey_hex = key.exportPublicKey().ToHex();
    const std::string test_prikey_hex = key.exportPrivateKey().ToHex();
    const std::string test_pubkey_pem = key.exportPublicKeyPEM();
    const std::string test_prikey_pem = key.exportPrivateKeyPEM();
    std::cout << "test_pubkey_hex: " << test_pubkey_hex << "\n"
                << "test_prikey_hex: " << test_prikey_hex << "\n"
                << "test_pubkey_pem: " << test_pubkey_pem << "\n"
                << "test_prikey_pem: " << test_prikey_pem 
                << std::endl;

    AsymKey imported_key_by_pem(FromPemStr(test_prikey_pem));
    assert(imported_key_by_pem.is_valid()); 
#endif
    const std::string msg{"Alice want to say hello to Bob"};
    const AsymKey ecdsa;
#if 0
    std::cout << "Signing / Verifying" << std::endl; 
    
    const AsymKey ecdsa;
       // const std::string pubkey = ecdsa.exportPublicPEM();
    const std::pair<BigNumber, BigNumber> rs = ecdsa.sign(msg);
    std::cout << "r  s -> " << rs.first.ToHex() << "  " << rs.second.ToHex() << std::endl; 
    std::cout << "verifying" << std::endl;
    std::cout << ecdsa.exportPublicKeyPEM() << std::endl; 
    if(!verify(msg, ecdsa.exportPublicKeyPEM(), rs)){
        std::cerr << "Verification failed" << std::endl;
    } else {
        std::cout << "Verification successful" << std::endl;
    }
#endif

    std::cout << "Creating HASH first " << std::endl; 
    //const std::string msg{"Alice want to say hello to Bob"};
    size_t digest_len(0);
    std::unique_ptr<unsigned char[]> hashMsg_ptr = hash_msg_str<>(msg, digest_len); 
    std::string hashmsg_str =  binTohexStr(hashMsg_ptr, digest_len); 
    std::cout << hashmsg_str << std::endl;
#if 0
    const std::pair<BigNumber, BigNumber> rs_sha_msg = ecdsa.sign_S256_str(hashmsg_str);
    std::cout << ecdsa.exportPublicKeyPEM() << std::endl; 
    std::cout << " r/s " << rs_sha_msg.first.ToHex() << "  " << rs_sha_msg.second.ToHex() << std::endl;
    if(!verify_S256_str(hashmsg_str, ecdsa.exportPublicKeyPEM(), rs_sha_msg)){
        std::cerr << "Verification failed" << std::endl;
    } else {
        std::cout << "Verification successful" << std::endl;
    }
     std::cout << "sign bytes" << std::endl; 
#endif
   
    //std::unique_ptr<unsigned char[]> hashMsg_ptr = hash_msg<>(msg, digest_len); 
    //std::cout << "Digest Length -> " << digest_len << std::endl;
    //std::cout << binTohexStr(hashMsg_ptr, digest_len) << std::endl;
    std::cout << ecdsa.exportPublicKeyPEM() << std::endl;
    const std::pair<BigNumber, BigNumber> rs = ecdsa.sign_S256_bytes(hashMsg_ptr,digest_len);
    std::cout << " r/s " << rs.first.ToHex() << "  " << rs.second.ToHex() << std::endl;
    if(!verify_S256_bytes(hashMsg_ptr,digest_len, ecdsa.exportPublicKeyPEM(), rs)){
        std::cerr << "Verification failed" << std::endl;
    } else {
        std::cout << "Verification successful" << std::endl;
    }


    std::cout << "key splitting & recover" << std::endl; 
    AsymKey randomKey;
    int t=5;
    int k=7;
    std::vector<KeyShare> shares = split(randomKey,t,k); 
    
    //pick 10 different sets of 10 shares and try to recreate the key
    //for (int i=0; i < 100; ++i){
#if 1 
        std::vector<KeyShare> shareSample;
        std::set<int> chosenNums; 
        
        while (shareSample.size () < t ){
            int index = rand() % (shares.size()-1) ; 
            if ( chosenNums.find(index) == chosenNums.end()){
                chosenNums.insert(index);
                shareSample.push_back(shares.at(index)); 
            }
        }
        
        // try to recover the secret
        std::cout << "randomKey -> " << randomKey.exportPrivateKey().ToHex() << std::endl; 
        AsymKey recoveredkey = recover(shareSample, 714); 
        std::cout << "randomKey -> " << randomKey.exportPrivateKey().ToHex() << "\n"
                    << "recoveredKey -> " << recoveredkey.exportPrivateKey().ToHex() 
                    << std::endl; 
        assert (randomKey.exportPrivateKey().ToHex() == recoveredkey.exportPrivateKey().ToHex() );
        assert(randomKey.is_valid()); 
        assert(recoveredkey.is_valid()); 
#endif
    //}
       

    const std::string additive_msg{ "I am a random message, hash me to get a big number" };
    const AsymKey alice_key;
    const AsymKey bob_key;

    const AsymKey alice_derived_key = derive_new_key(alice_key, additive_msg);
    std::cout << alice_derived_key.exportPrivateKey().ToHex() << std::endl; 
    assert (alice_derived_key.is_valid());

    const AsymKey bob_derived_key = derive_new_key(bob_key, additive_msg);
    //EXPECT_TRUE(bob_derived_key.is_valid());
    std::cout << "Finishing" << std::endl; 
    return 0;
}
