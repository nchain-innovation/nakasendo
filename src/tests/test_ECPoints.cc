/// Define test module name with debug postfix

#include <gtest/gtest.h>

#include <ECPoint/ECPoint.h>
#include <BigNumbers/BigNumbers.h>
#include <iostream>
#include <memory>
#include <tuple>

//BOOST_AUTO_TEST_SUITE(test_suite_ECPoints)

/*test case : test the addition of ECPoints, and compare the result*/
TEST(ECPointTest, testECPointAdditionAndComparasion)
{
    
    ECPoint ec1, ec2, ec3;
    ec1.SetRandom();
    ec2.SetRandom();
    ec3.SetRandom();
    EXPECT_EQ((( ec1 + ec2) + ec3), (ec1 + (ec2 + ec3)));
}


/* test case : test the != operator of ECPoint */
TEST(ECPointTest, testECPointComparasion1)
{
    ECPoint ec1, ec2;
    ec1.FromHex("03A519004B8A4222CF06E5BFA825266E0DCC6A9C99E408D043A2D0D1C33AE8895F");
    ec2.FromHex("025F0F2C3C4A73FA39DA5E444481BC43CAB388E174517C2F63E1E8BFC1036D66B1");
    EXPECT_TRUE(ec1 != ec2);
    EXPECT_EQ(ec1+ec2, ec2+ec1);
}

TEST(ECPointTest, testECPointComparasionFromDec)
{
    ECPoint ec1, ec2;
    ec1.FromDec("395542064311071069906152228988473994820339713646861489821554896924846964108123");
    ec2.FromDec("447598968722653408227263864668198675919513265003103330993736530144745047889284");
    EXPECT_TRUE(ec1 != ec2);
    EXPECT_EQ(ec1+ec2, ec2+ec1);
}

/* test case : test the point on curve */
TEST(ECPointTest, testECPointCheckPointOnCurve)
{
    ECPoint ec1;
    ec1.SetRandom();
    EXPECT_TRUE(ec1.CheckOnCurve());
}

/* test case : test the point is at infinity */
TEST(ECPointTest, testECPointCheckInfinity)
{
    ECPoint ec1;
    ec1.SetRandom();
    EXPECT_TRUE(!ec1.CheckInfinity());
}


TEST(ECPointTest, testECPointGeneratorForAllCurves)
{
    std::vector<std::tuple<int, std::string, std::string>> curveList = getCurveList();
    for (auto nidTuple : curveList){
        ECPoint ec1(std::get<0>(nidTuple));
        ec1.getGenerator();
    }
}

TEST(ECPointTest, testECPointGroupDegreeForAllCurves)
{
    std::vector<std::tuple<int, std::string, std::string>> curveList = getCurveList();
    for (auto nidTuple : curveList)
    {
        ECPoint ec1(std::get<0>(nidTuple));
        ec1.getECGroupDegree();
    }
}


TEST(ECPointTest, testECPointGroupOrderForAllCurves)
{
    std::vector<std::tuple<int, std::string, std::string>> curveList = getCurveList();
    for (auto nidTuple : curveList)
    {
        ECPoint ec1(std::get<0>(nidTuple));
        ec1.getECGroupOrder().ToDec();
    }
}

/* test case : to test the copy Constructor of ECPoint */
TEST(ECPointTest, testECPointCopyConstructor)
{
    ECPoint ec1;
    ec1.SetRandom();
    ECPoint ec2(ec1);
    EXPECT_EQ(ec1, ec2);
}

/*test case : to test the copy assignment operator of ECPoint*/
TEST(ECPointTest, testECPointCopyAssignment)
{
    ECPoint ec1;
    ECPoint ec2;
    ec1.SetRandom();
    ec2.SetRandom();
    ec2 = ec1;
    //EXPECT_EQ(ec1, ec2);
}

/*test case : to test the double of ECPoint*/
TEST(ECPointTest, testECPointDouble)
{
    ECPoint ec1;
    ec1.SetRandom();
    ECPoint ec2 = ec1;
    EXPECT_EQ(ec1+ec1, ec2.Double());
    EXPECT_TRUE(ec2.Double().CheckOnCurve());
}

/*test case : to test the invert of ECPoint*/
TEST(ECPointTest, testECPointInvert)
{
    ECPoint ec1;
    ec1.SetRandom();
    ECPoint ec2 = ec1;
    ec1.Invert();
    EXPECT_TRUE(ec1 != ec2);
    EXPECT_TRUE(ec1.ToHex().compare(2, std::string::npos, ec2.ToHex(), 2, std::string::npos) == 0);
    EXPECT_TRUE(ec1.CheckOnCurve());
}

/* test case : to test getCurveList and getNidForString  */
TEST(ECPointTest, testECPointGetCurveList)
{
    std::vector<std::tuple<int, std::string, std::string>> curveList = getCurveList();

    // verify the test data
    for (auto nidTuple : curveList)
    {
	    EXPECT_EQ(getNidForString(std::get<1>(nidTuple)),  std::get<0>(nidTuple));
    }
}

/*test case : to test the Multiply Hex of ECPoint*/
TEST(ECPointTest, testECPointMulHex)
{
    ECPoint ec1;
    ec1.SetRandom();
    
    BigNumber bnm , bnn;
    bnm.generateRandHex(1024);
    bnn.generateRandHex(1024);

    //ECPoint ec2 = ec1.MulHex(bnm.ToHex(), bnn.ToHex());
    ECPoint ec2 = Multiply(ec1, bnm, bnn); 
    EXPECT_TRUE(ec2.CheckOnCurve());

    std::string es;
    //ECPoint ec3 = ec1.MulHex(bnm.ToHex(), es);
    ECPoint ec3 = ec1 * bnm; 
    EXPECT_TRUE(ec3.CheckOnCurve());
}

TEST(ECPointTest, testECPointSetAffineCoordinatesConstructor){
    ECPoint ec1;
    ec1.SetRandom();
    std::pair<BigNumber, BigNumber> coord = ec1.GetAffineCoords();
    //BigNumber bnX, bnY;
    //bnX.FromHex(coord.first);
    //bnY.FromHex(coord.second);
    ECPoint ec2(coord.first, coord.second);

    EXPECT_EQ(ec1, ec2);
}

TEST(ECPointTest, testECPointMultiplyByGenerator){
    BigNumber b; 
    b.generateRandHex();

    ECPoint pt = MultiplyByGeneratorPt (b);
    EXPECT_TRUE(pt.CheckOnCurve());

}

TEST(ECPointTest, testECParamsCalls){
    const int curve_id = 714;
    std::string n_val_hard("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    BigNumber fixedVal; 
    fixedVal.FromHex(n_val_hard); 
    BigNumber n_val = GroupOrder(curve_id);
    EXPECT_EQ(fixedVal, n_val);

}
