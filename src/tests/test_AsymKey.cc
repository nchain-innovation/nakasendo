#include <gtest/gtest.h>

#include <AsymKey/AsymKey.h>
#include <BigNumbers/BigNumbers.h>
#include <Utils/conversions.h>
#include <ECPoint/ECPoint.h>
#include <Polynomial/Polynomial.h>
#include <Utils/hashing.h>
#include <SecretShare/KeyShare.h>
#include <SecretShare/SecretSplit.h>

#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include <set>

#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#if 0 
std::string test_help_hash(const std::string& crMsg)// Hash a random str to hex
{
    /// This is a quick version hashing small string
    auto buff2hexstr_helper = [](unsigned char* buff, size_t buff_len)->std::string
    {
        /// OPENSSL_buf2hexstr doesn't work as expected, it returned hex string with parts separated by comma (file $OPENSSL_ROOT_DIR/crypto/o_str.c:OPENSSL_buf2hexstr)
        /// Use manual converter here could give flexibility https://stackoverflow.com/questions/10723403/char-array-to-hex-string-c
        constexpr char hexmap[] = "0123456789ABCDEF";
        std::string hexstr(2 * buff_len, ' ');

        for (size_t i = 0; i < buff_len; ++i)
        {
            hexstr[2 * i] = hexmap[(buff[i] & 0xF0) >> 4];
            hexstr[2 * i + 1] = hexmap[(buff[i] & 0x0F) >> 0];
        }
        return std::move(hexstr);
    };

    /// For longer string, need to use buffer and sha update mechanism
    unsigned char hash_buff[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(crMsg.c_str()), crMsg.size(), hash_buff);
    const std::string output = buff2hexstr_helper(hash_buff, SHA256_DIGEST_LENGTH);
    return std::move(output);
}

std::string get_key_info(const AsymKey& crKey)
{
    std::stringstream ss;
    ss << "groupID:" << crKey.GroupNid() << "\n";
    ss << "   G_x:" << crKey.Group_G_x() << "\n";
    ss << "   G_y:" << crKey.Group_G_y() << "\n";
    ss << "     p:" << crKey.Group_p()   << "\n";
    ss << "     a:" << crKey.Group_a()   << "\n";
    ss << "     b:" << crKey.Group_b()   << "\n";
    ss << "pub_hex:[" << crKey.exportPublicHEX().first <<"," <<crKey.exportPublicHEX().second << "]\n";
    ss << "pri_hex:[" << crKey.exportPrivateHEX() << "]\n";
    ss << "pub_pem:\n" << crKey.exportPublicPEM();
    ss << "pri_pem:\n" << crKey.exportPrivatePEM() << "\n";
    return std::move(ss.str());
}

std::string get_failed_key_derived_info(const AsymKey& crKey, const std::string& crAdditiveMsg, const AsymKey& crDerivedPrivateKey, const std::string& crDerivedPublicKey)
{
    std::stringstream ss;
    ss << "__AdditiveMsg_________________" << crAdditiveMsg << "_["<<test_help_hash(crAdditiveMsg)<<"]\n";
    ss << "__key_________________________\n" << get_key_info(crKey) ;
    ss << "__derived key_________________\n" << get_key_info(crDerivedPrivateKey);
    ss << "__derived pub key_____________\n" << crDerivedPublicKey ;
    ss << "__derived pub key hex_________[" << pubkey_pem2hex(crDerivedPublicKey).first << "," << pubkey_pem2hex(crDerivedPublicKey).second << "]\n";
    const std::string test_derived_pubkey = crDerivedPrivateKey.exportPublicPEM();
    if (test_derived_pubkey != crDerivedPublicKey)
        ss << "__failed__________________ : [derived pub key] doesn't match with the public key of the [derived key] (private)\n";
    else
        ss << "\n";
    return std::move(ss.str());
}
#endif 
TEST(AsymKeyTest, test_default_constructor){
    AsymKey key;
    EXPECT_TRUE(key.is_valid());
}

TEST(AsymKeyTest, test_default_group_information_secp256k1)
{
    AsymKey key;
    EXPECT_TRUE(key.is_valid());

    const int test_groupID = key.GroupNid();
    std::cout << test_groupID << std::endl; 
    EXPECT_EQ(test_groupID, OBJ_txt2nid("secp256k1"));

    ECPoint gx = key.Group_G();
    BigNumber p = key.Group_p()  ;
    BigNumber a = key.Group_a()  ;
    BigNumber b = key.Group_b()  ;
    BigNumber order = key.Group_Order()  ;

    // https://en.bitcoin.it/wiki/Secp256k1
    EXPECT_EQ(gx.ToHex() , "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    EXPECT_EQ(gx.ToHex(false), "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    EXPECT_EQ(p.ToHex(),  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    EXPECT_EQ(a.ToHex(), "0");
    EXPECT_EQ(b.ToHex(), "07");
    EXPECT_EQ(order.ToHex(), "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
}


TEST(AsymKeyTest, test_constructor_with_groupnid)
{
    /// Construct asymkey with all possible ec curves
    const auto nb_curves = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve *curve_list = (EC_builtin_curve *)OPENSSL_malloc(sizeof(EC_builtin_curve) * nb_curves);
    const auto nb_curves_r = EC_get_builtin_curves(curve_list, nb_curves);

    EXPECT_EQ(nb_curves_r, nb_curves);

    size_t i{0};
    while (i < nb_curves)
    {
        const int curve_groupNID = curve_list[i].nid;

        if (curve_groupNID != 749 && curve_groupNID != 750){
            AsymKey key(curve_groupNID);
            EXPECT_TRUE(key.is_valid());
        }
        ++i;
    }
    OPENSSL_free(curve_list);
}

TEST(AsymKeyTest, test_randomness)
{
    const size_t nbSample = 10;
    std::vector<std::pair<ECPoint, BigNumber>> list_keystr;
    /// Generate list of keys
    for (size_t i = 0; i < nbSample; ++i) 
    {
        AsymKey key;
        list_keystr.push_back(std::make_pair(key.exportPublicKey(), key.exportPrivateKey()));
    }

    for (size_t i = 0; i < nbSample; ++i){
        for (size_t j = i+1; j < nbSample; ++j){

            EXPECT_NE(ComparePoints(list_keystr[i].first, list_keystr[j].first), true);
            EXPECT_NE(list_keystr[i].second == list_keystr[j].second, true);
        }
    }
}



TEST(AsymKeyTest, test_IO){
    const size_t nbCases = 50;
    for (size_t i = 0; i < nbCases; ++i){
        const AsymKey test_key;
    
        const std::string test_prikey_pem = test_key.exportPrivateKeyPEM();


        {
            AsymKey imported_key_by_pem(FromPemStr(test_prikey_pem));
            EXPECT_TRUE(imported_key_by_pem.is_valid());
            EXPECT_EQ(imported_key_by_pem.exportPublicKey(), test_key.exportPublicKey()); 
            EXPECT_EQ(imported_key_by_pem.exportPrivateKey(), test_key.exportPrivateKey());
        }

    }

}

TEST(AsymKeyTest, test_IO_more){
    const size_t nbSample = 10;
    for (size_t i = 0; i < nbSample; ++i){
        AsymKey key;
        const std::string pub_key_pem = key.exportPublicKeyPEM();
        ECPoint recover_pub_key = pubkey_pem2hex(pub_key_pem);
        EXPECT_EQ(key.exportPublicKey(), recover_pub_key); 
    }
}

TEST(AsymKeyTest, test_Sig_Verify){
    const std::string msg{"Alice want to say hello to Bob"};
    const int nb_iter = 10;
    for (int i = 0; i < nb_iter; ++i){
        // default curve key -> 714 to the verify
        const AsymKey ecdsa;
       const std::string pubkey = ecdsa.exportPublicKeyPEM();
       const std::pair<BigNumber, BigNumber> rs = ecdsa.sign(msg);
       const bool verify_ok = verify(msg, pubkey, rs);
       EXPECT_TRUE(verify_ok); 
    }
}


TEST(AsymKeyTest, test_SigS256_Verify){
    const std::string msg{"Alice want to say hello to Bob"};
    size_t digest_len(0);

    std::unique_ptr<unsigned char[]> hashMsg_ptr = hash_msg_str<>(msg, digest_len); 
    std::string hash_msg = binTohexStr(hashMsg_ptr, digest_len);

    const int nb_iter = 10;
    for (int i = 0; i < nb_iter; ++i){
        const AsymKey ecdsa;
        const std::string pubkey = ecdsa.exportPublicKeyPEM();
        const std::pair<BigNumber, BigNumber> rs = ecdsa.sign_S256_str(hash_msg);
        const bool verify_ok = verify_S256_str(hash_msg, ecdsa.exportPublicKeyPEM(), rs);
        EXPECT_TRUE(verify_ok);
        // create a DER-SIG & verify with that. 
        BigNumber rTest, sTest; 
        rTest.FromHex(rs.first.ToHex());
        sTest.FromHex(rs.second.ToHex());
        size_t len(-1);
        std::unique_ptr<unsigned char[]>  sigDERTestWithHash = DEREncodedSignature(rTest,sTest,len);
        const bool verify_ok_der = verifyDER_S256_str(hash_msg, pubkey, sigDERTestWithHash, len);
        EXPECT_TRUE(verify_ok_der); 
    }
}

TEST(AsymKeyTest, test_SigRawBytes_Verify){
    const std::string msg{"Alice want to say hello to Bob"}; 
    size_t digest_len(0);
    std::unique_ptr<unsigned char[]> hashMsg_ptr = hash_msg_str<>(msg, digest_len); 
    std::string hash_msg_str = binTohexStr(hashMsg_ptr, digest_len);

    const int nb_iter = 10;
    for (int i = 0; i < nb_iter; ++i)
    {
        const AsymKey ecdsa;
        const std::string pubkey = ecdsa.exportPublicKeyPEM();
        const std::pair<BigNumber, BigNumber> rs = ecdsa.sign_S256_bytes(hashMsg_ptr,digest_len);
        const bool verify_ok = verify_S256_bytes(hashMsg_ptr,digest_len, pubkey, rs);
        EXPECT_TRUE(verify_ok);

        BigNumber rTest, sTest; 
        rTest.FromHex(rs.first.ToHex());
        sTest.FromHex(rs.second.ToHex());
        size_t len(-1);
        std::unique_ptr<unsigned char[]>  sigDERTestWithHash = DEREncodedSignature(rTest,sTest,len);
        const bool verify_ok_der = verifyDER_S256_str(hash_msg_str, pubkey, sigDERTestWithHash, len);
        EXPECT_TRUE(verify_ok_der);
    }
}

TEST(AsymKeyTest, test_private_key_split){
    AsymKey randomKey;
    int t=5;
    int k=7;
    std::vector<KeyShare> shares = split(randomKey,t,k); 
   
    //pick 10 different sets of 10 shares and try to recreate the key
    for (int i=0; i < 100; ++i){
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
        
        AsymKey recoveredkey = recover(shareSample, 714); 
        
        EXPECT_EQ(recoveredkey.exportPrivateKey(), randomKey.exportPrivateKey()); 
        
        //BOOST_TEST (recoveredkey.exportPrivateHEX () == randomKey.exportPrivateHEX()); 
        
    }
    
}
#if 0 
BOOST_AUTO_TEST_CASE(test_SigEx_Verify)
{
    const std::string msg{ "Alice want to say hello to Bob" };
    const int nb_iter = 10;
    for (int i = 0; i < nb_iter; ++i)
    {
        /// This part manage to get the random ephemeral key and its inverse
        const AsymKey random_hex;
        const std::string G_x_hex = random_hex.Group_G_x();
        const std::string G_y_hex = random_hex.Group_G_y();
        const std::string G_n_hex = random_hex.Group_n();
        const std::string k_hex = random_hex.exportPrivateHEX();

        BigNumber Gx; Gx.FromHex(G_x_hex);
        BigNumber Gy; Gy.FromHex(G_y_hex);
        BigNumber Gn; Gn.FromHex(G_n_hex);
        BigNumber k; k.FromHex(k_hex);
        BigNumber inv_k; inv_k = Inv_mod(k, Gn);
        ECPoint G(Gx, Gy);
        const ECPoint kG = G.MulHex(k_hex, std::string());
        const std::pair<std::string, std::string> kG_xy = kG.GetAffineCoords_GFp();
        const std::string r_hex = kG_xy.first;
        const std::string inv_k_hex = inv_k.ToHex();

        const AsymKey ecdsa;
        const int& curveid(714);
        const std::string pubkey = ecdsa.exportPublicPEM();
        const std::pair<std::string, std::string> rs = ecdsa.sign_ex(msg, inv_k_hex, r_hex);
        const std::string sig_r_hex = rs.first;
        const bool verify_ok = verify(msg, pubkey, rs, curveid);
        BOOST_CHECK(sig_r_hex == r_hex);
        BOOST_CHECK(verify_ok);
    }
}

BOOST_AUTO_TEST_CASE(test_Sig_Verify_Random)
{
    const size_t nbIter = 10;
    for (size_t i = 0; i < nbIter; ++i)
    {
        //// Use Key to generate different strings. It is not really random, but it generate different string each iteration
        const AsymKey randomKey;
        const int& curveid(714);
        const std::string random_str = randomKey.exportPublicHEXStr();

        const AsymKey ecdsa;
        const std::string pubkey = ecdsa.exportPublicPEM();
        const std::pair<std::string, std::string> rs = ecdsa.sign(random_str);
        const bool verify_ok = verify(random_str, pubkey, rs, curveid);
        BOOST_CHECK(verify_ok);
    }
}

BOOST_AUTO_TEST_CASE(test_Sig_DER_Verify_Random)
{
    const size_t nbIter = 10;
    for (size_t i = 0; i < nbIter; ++i)
    {
        //// Use Key to generate different strings. It is not really random, but it generate different string each iteration
        const AsymKey randomKey;
        const std::string random_str = randomKey.exportPublicHEXStr();

        const AsymKey ecdsa;
        const int& curveid(714);
        const std::string pubkey = ecdsa.exportPublicPEM();
        const std::pair<std::string, std::string> rs = ecdsa.sign(random_str);
        // create BigNumber versions of the r & s
        BigNumber rTest;
        rTest.FromHex(rs.first);
        BigNumber sTest;
        sTest.FromHex(rs.second);
        // create a DER format of the signature
        size_t len(-1); 
        std::unique_ptr<unsigned char[]>  sigDERTest = DEREncodedSignature(rTest,sTest,len);
        const bool verify_ok = verifyDER(random_str, pubkey, sigDERTest, len, curveid);
        BOOST_CHECK(verify_ok);
    }
}

BOOST_AUTO_TEST_CASE(test_SharedSecret)
{   
    // Test a few iteration with keys randomly generated
    const size_t nbIter = 10;
    for (size_t i = 0; i < nbIter; ++i)
    {
        const AsymKey alice_key;
        const AsymKey bob_key;

        const std::string alice_pub_key = alice_key.exportPublicPEM();
        const std::string bob_pub_key = bob_key.exportPublicPEM();

        const std::string shared_secret_from_bob = bob_key.exportSharedSecretHex(alice_pub_key);
        const std::string shared_secret_from_alice = alice_key.exportSharedSecretHex(bob_pub_key);
        BOOST_CHECK(!shared_secret_from_bob.empty());
        BOOST_CHECK(shared_secret_from_bob == shared_secret_from_alice);
    }
}

BOOST_AUTO_TEST_CASE(test_key_derive_wp0042)
{   
    // Test a few iteration with keys randomly generated
    const size_t nbIter = 10;
    size_t nbFailed{0};
    for (size_t i = 0; i < nbIter; ++i)
    {
        const std::string additive_msg{ "I am a random message, hash me to get a big number" };
        const AsymKey alice_key;
        const AsymKey bob_key;
        const std::string alice_pub_key = alice_key.exportPublicPEM();
        const std::string bob_pub_key = bob_key.exportPublicPEM();

        const std::string alice_derived_pub_key = derive_pubkey(alice_pub_key, additive_msg);
        const std::string bob_derived_pub_key = derive_pubkey(bob_pub_key, additive_msg);

        const AsymKey alice_derived_key = alice_key.derive(additive_msg);
        BOOST_CHECK(alice_derived_key.is_valid());
        const AsymKey bob_derived_key = bob_key.derive(additive_msg);
        BOOST_CHECK(bob_derived_key.is_valid());

        const std::string alice_derived_pub_key_test = alice_derived_key.exportPublicPEM();
        const std::string bob_derived_pub_key_test = bob_derived_key.exportPublicPEM();
        BOOST_CHECK(alice_derived_pub_key == alice_derived_pub_key_test);
        BOOST_CHECK(bob_derived_pub_key == bob_derived_pub_key_test);
    }
}

BOOST_AUTO_TEST_CASE(test_private_key_split)
{
    AsymKey randomKey;
    int t=5;
    int k=7;
    std::vector<KeyShare> shares = randomKey.split(t,k); 

    //pick 10 different sets of 10 shares and try to recreate the key
    for (int i=0; i < 100; ++i){
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
        
        AsymKey recoveredkey; 
        recoveredkey.recover(shareSample);
        
        BOOST_TEST (recoveredkey.exportPrivateHEX () == randomKey.exportPrivateHEX()); 
        
    }
    
}

BOOST_AUTO_TEST_CASE(test_private_key_with_encryption)
{
    for (int i = 0; i < 5; ++i )
    {

        // Part (a) - test get (write) private key
        // export
        AsymKey testKeyA ;
        std::string passPhrase ( "I am She-Ra!!!" ) ;    
        const std::string test_prikey_pem_encrypted =  testKeyA.exportPrivatePEMEncrypted( passPhrase ) ;

        // Check the contents of key are as expected
        BOOST_CHECK( boost::algorithm::contains( test_prikey_pem_encrypted, "-----BEGIN EC PRIVATE KEY-----" ) ) ;
        BOOST_CHECK( boost::algorithm::contains( test_prikey_pem_encrypted, "-----END EC PRIVATE KEY-----" ) ) ;
        BOOST_CHECK( boost::algorithm::contains( test_prikey_pem_encrypted, "AES-256-CBC" ) ) ;
        BOOST_CHECK( boost::algorithm::contains( test_prikey_pem_encrypted, "ENCRYPTED" ) ) ;

        // Part (b) - test set (read) private key
        // import
        AsymKey testKeyB ;
        std::string incorrectPassPhrase ( "By the power of Grayskull..." ) ;
        
        testKeyB.importPrivatePEMEncrypted( test_prikey_pem_encrypted, passPhrase ) ;
        BOOST_CHECK( testKeyB.is_valid( ) ) ;
        
        // check the imported/imported key is the same as the original
        const std::string testKeyAString =  testKeyA.exportPrivatePEM(  ) ;
        const std::string testKeyBString =  testKeyB.exportPrivatePEM(  ) ;
        BOOST_CHECK( testKeyAString == testKeyAString ) ;
        
        // Check the PEM throws an error with an incorrect pass pharse
        BOOST_CHECK_THROW
            ( 
                testKeyB.importPrivatePEMEncrypted( test_prikey_pem_encrypted, incorrectPassPhrase ) ; , 
                std::runtime_error 
            );  
    }
}

BOOST_AUTO_TEST_CASE(test_fixbug_SL364_sign_ex)
{
    //// https://nchain.atlassian.net/browse/SL-364
    const std::string msg{ "I love deadlines. I love the whooshing noise they make as they go by." };
    /// This part manage to get the random ephemeral key and its inverse
    const AsymKey random_hex;
    const std::string G_x_hex = random_hex.Group_G_x();
    const std::string G_y_hex = random_hex.Group_G_y();
    const std::string G_n_hex = random_hex.Group_n();
    const std::string d_hex{"B0BD078D3A70DA8407398E764712680B762EDC0AE417B71AC29DB1DB19E6135F"};
    const std::string k_hex{"C5BDF8673298782F3587BDF2BAC0A5FA5E37C1B48A74426007C02A8A140A26F7"};
    const std::string test_sig_s_hex{ "B1164242138D07C2828CF4E71FECFFB414EA78DA828C352E3381773788065F6B"};// Input from python ecdsa

    BigNumber Gx; Gx.FromHex(G_x_hex);
    BigNumber Gy; Gy.FromHex(G_y_hex);
    BigNumber Gn; Gn.FromHex(G_n_hex);
    BigNumber k; k.FromHex(k_hex);
    BigNumber inv_k; inv_k = Inv_mod(k, Gn);
    const std::string invk_hex = inv_k.ToHex();
    ECPoint G(Gx, Gy);
    const ECPoint kG = G.MulHex(k_hex, std::string());
    const std::pair<std::string, std::string> kG_xy = kG.GetAffineCoords_GFp();
    const std::string r_hex = kG_xy.first;
    const std::string inv_k_hex = inv_k.ToHex();

    AsymKey ecdsa; ecdsa.importPrivateHEX(d_hex);
    const int& curveid(714);
    const std::string pubkey = ecdsa.exportPublicPEM();
    const std::pair<std::string, std::string> rs = ecdsa.sign_ex(msg, inv_k_hex, r_hex);
    const std::string sig_r_hex = rs.first;
    const std::string sig_s_hex = rs.second;
    const bool verify_ok = verify(msg, pubkey, rs, curveid);
    BOOST_CHECK(sig_r_hex == r_hex);
    BOOST_CHECK(sig_s_hex == test_sig_s_hex);
    BOOST_CHECK(verify_ok);
}

#endif