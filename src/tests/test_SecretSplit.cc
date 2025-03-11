
#include <gtest/gtest.h>

#include <BigNumbers/BigNumbers.h>
#include <Polynomial/Polynomial.h>
#include <Polynomial/LGInterpolator.h>
#include <SecretShare/SecretSplit.h>
#include <SecretShare/KeyShare.h>

#include <string>
#include <iostream>
#include <set>


TEST(SECRETSPLIT_Test, test_secret_split){
    int threshold = 20;
    int maxshares = 100;
    
    int degree = threshold -1; 
    int numberShareCombinations = 10 ; 
    
    BigNumber mod; 
    mod.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");  
    
      // a randomly chosen large number for our secret
    
    BigNumber zero ;
    zero.Zero(); 
    BigNumber theSecret = GenerateRandRange (zero, mod, 512);
    
    Polynomial poly(degree, mod, theSecret);
    
    std::vector<KeyShare> shares = make_shared_secret (poly, threshold, maxshares);
    for (int i=0; i < numberShareCombinations; ++i){
        std::vector<KeyShare> shareSample;
        std::set<int> chosenNums; 
        
        while (shareSample.size () < threshold ){
            int index = rand() % (shares.size()-1) ; 
            if ( chosenNums.find(index) == chosenNums.end()){
                chosenNums.insert(index);
                shareSample.push_back(shares.at(index)); 
            }
        }
        
        // try to recover the secret
        
        BigNumber recovered_secret; 
        recovered_secret.Zero(); 
        recovered_secret = RecoverSecret(shareSample, mod); 
        
        EXPECT_EQ(recovered_secret.ToHex (), theSecret.ToHex()); 
        
    }
}

TEST(SECRETSPLIT_Test, test_secret_split_failures ){
    
    int threshold = 20;
    int maxshares = 100;
    
    int degree = threshold -1; 
    int numberShareCombinations = 10 ; 
    
    BigNumber mod; 
    mod.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");  
    
      // a randomly chosen large number for our secret
    
    BigNumber zero ;
    zero.Zero(); 
    BigNumber theSecret = GenerateRandRange (zero, mod, 512);
    
    Polynomial poly(degree, mod, theSecret);
    
    std::vector<KeyShare> shares = make_shared_secret (poly, threshold, maxshares);
    for (int i=0; i < numberShareCombinations; ++i){
        std::vector<KeyShare> shareSample;
        std::set<int> chosenNums; 
        
        while (shareSample.size () < threshold-1 ){
            int index = rand() % (shares.size()-1) ; 
            if ( chosenNums.find(index) == chosenNums.end()){
                chosenNums.insert(index);
                shareSample.push_back(shares.at(index)); 
            }
        }
        
        // try to recover the secret
        
        BigNumber recovered_secret; 
        recovered_secret.Zero(); 
        
        
        EXPECT_THROW(RecoverSecret(shareSample, mod), std::runtime_error); 
        //BOOST_CHECK_THROW(
        //    recovered_secret = RecoverSecret(shareSample, mod); ,
        //    std::runtime_error
        //); 
        
    }
}

