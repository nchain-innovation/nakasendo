
import pathlib
import ast
import unittest
from PyNakasendo import PyNakasendo

# using the integer value of NID secp256k1, which is 714
nid_Id = 714
dec = 1
hex = 0

class ECPointTests(unittest.TestCase):
    def test_GenerateRandomECHex(self):

        # Generating Random EC Points
        for x in range(100):

            # Generate a Random EC Point with default NID ==> NID_secp256k1
            #actual_value = PyECPoint.GenerateRandomEC( 0, hex, True )
            curve_id : int = 714
            ec_pt = PyNakasendo.PyECPoint.PyECPoint((curve_id))
            ec_pt.SetRandom()
            ec_ptr_hex  = ec_pt.ToHex()
  
            # Verifying the the length of actual value as 66
            assert len(ec_ptr_hex) == 66, "Test failed"

    def test_CheckOnCurve(self):
    # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt.SetRandom()
            assert ec_pt.CheckOnCurve(), "test failed"

    def test_GetAffineCoOrdinates(self):
    # Generating Random EC
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt.CheckOnCurve(), "test failed"
            x_axis, y_axis = ec_pt.GetAffineCoords()
            assert len(x_axis.ToHex()) == 62 or len(x_axis.ToHex()) == 64, "Test failed"


    def test_GetAffineCoOrdinatesOnCurve(self):
    # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt.SetRandom()
            # Check if the point is on the curve with t
            assert ec_pt.CheckOnCurve(), "test failed"
            # EC Point GetAffineCoOrdinates_GFp with supplied curve
            x_axis, y_axis = ec_pt.GetAffineCoords()
            assert len(x_axis.ToHex()) == 62 or len(x_axis.ToHex()) == 64, "Test failed"
            

    def test_AddECFromHex(self):
    #Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
        with open("./test_data/testData_AddECFromHex", "r") as addEChex_txt:
            for x in addEChex_txt:
                hexNumber = x.split(",")
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.FromHex(hexNumber[0])
            ec_pt_b = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_b.FromHex(hexNumber[1])
            assert ec_pt_a.CheckOnCurve(), "test failed"
            assert ec_pt_b.CheckOnCurve(), "test failed"

            ec_pt_sum = ec_pt_a + ec_pt_b
            assert ec_pt_sum.CheckOnCurve(), "test failed"

            # Verifying the actual value with expected value
            assert ec_pt_sum.ToHex() == hexNumber[2].rstrip("\n"), "Test failed"

    def test_MultiplyScalarM(self):
    # Generating Random EC Points
        for x in range(100):

            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve()
            # create a bignumber
            val1 = PyNakasendo.PyBigNumber.PyBigNumber()
            val1.GenerateRandHex()

            new_val = ec_pt_a * val1 
            # Verifying the actual value with expected value
            assert len(new_val.ToHex()) == 66, "Test failed"




    def test_AddECFromHex(self):

        #Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
        with open("./test_data/testData_AddECFromHex", "r") as addEChex_txt:
            for x in addEChex_txt:

                hexNumber = x.split(",")
                ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714); 
                ec_pt_a.FromHex(hexNumber[0]); 
                # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
                assert ec_pt_a.CheckOnCurve(), "Test failed"

                ec_pt_b = PyNakasendo.PyECPoint.PyECPoint(714); 
                ec_pt_b.FromHex(hexNumber[1]); 
                actual_value = ec_pt_a + ec_pt_b

                ec_pt_res = PyNakasendo.PyECPoint.PyECPoint(714); 
                ec_pt_res.FromHex(hexNumber[2].rstrip("\n")); 
                # Verifying the actual value with expected value
                assert actual_value == ec_pt_res



    def test_MultiplyScalarMN(self):

        # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1s
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve(), "Test failed"

            #Generate a Random Big number M and N using BigNumberAPIs
            bigNumbM = PyNakasendo.PyBigNumber.PyBigNumber()
            bigNumbM.GenerateRandHex(257)
            bigNumbN = PyNakasendo.PyBigNumber.PyBigNumber()
            bigNumbN.GenerateRandHex(128)

            # EC Point Scalar multiply with default NID => NID_secp256k1
            actual_value = PyNakasendo.PyECPoint.Multiply(ec_pt_a, bigNumbM, bigNumbN)

            # Verifying the the length of actual value as 66
            assert len(actual_value.ToHex()) == 66, "Test failed"

    def test_MultiplyScalarMOnCurve(self):

        # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()

            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve() , "Test failed"

            val1 = PyNakasendo.PyBigNumber.PyBigNumber()
            val1.GenerateRandHex()
            # EC Point Scalar multiply on curve with supplied ID
            actual_value = ec_pt_a * val1

            # Verifying the actual value with expected value
            assert len(actual_value.ToHex()) == 66, "Test failed"



    def test_CheckInfinityFromHex(self):

        # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve() , "Test failed"
            assert ec_pt_a.CheckInfinity() is False, "Test Failed"

    def test_CheckOnCurveFromHexOnCurve(self):

        # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()


            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve(), "Test failed"
            assert ec_pt_a.CheckInfinity() is False, "Test failed"

    def test_CompareECPoint(self):

        # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()
            ec_pt_b = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_b.SetRandom()

            assert ec_pt_a.CheckOnCurve(), "Test Failed"
            assert ec_pt_b.CheckOnCurve(), "Test Failed"
            #Compare two given ECPoints
            assert ec_pt_a != ec_pt_b, "Test Failed"


    def test_DoubleFromHex(self):

        # Generating Random EC Points
        for x in range(100):

            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve(), "Test failed"


            #Double the ECPoint in hex with the default NID ==> NID_secp256k1
            ec_pt_b = ec_pt_a.Double()

            # Verifying the the length of actual value as 66
            assert len(ec_pt_b.ToHex()) == 66, "Test failed"


    def test_InvertFromHex(self):

        # Generating Random EC Points
        for x in range(100):

            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()
            

            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve(), "Test failed"

            #Invert the ECPoint in hex with the default NID ==> NID_secp256k1
            ec_pt_a.Invert()

            # Verifying the the length of actual value as 66
            assert len(ec_pt_a.ToHex()) == 66, "Test failed"


    def test_GetGenerator(self):
        # Generating Random EC Points
        for x in range(100):

            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(714)
            ec_pt_a.SetRandom()

            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve(), "Test failed"

            #EC Point Generator with the supplied curve ID
            ec_pt_gen = ec_pt_a.GetGenerator()

            # Verifying the the length of actual value as 66
            assert len(ec_pt_gen.ToHex()) == 66, "Test failed"

    def test_GetGroupDegreeFromHex(self):

        # Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
        with open("./test_data/testData_GetGroupDegree", "r") as getGrpDegree_txt:#Test data are generated from https://svn.python.org/projects/external/openssl-0.9.8a/crypto/ec/ec_curve.c
            for x in getGrpDegree_txt:

                # Reading the line of the file as string and splitting into list
                nidID_Degree_Value = x.split(",")

                # Generate a Random EC Point with default NID ==> NID_secp256k1
                ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(int(nidID_Degree_Value[0]))
                ec_pt_a.SetRandom()

                # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
                assert ec_pt_a.CheckOnCurve(), "Test failed"

                #EC Point Group Degree with supplied curve
                actual_value = ec_pt_a.GetECGroupDegree()
                # Verifying the actual value with the expected value.
                assert actual_value == int(nidID_Degree_Value[1]), "Test failed"


    def test_GetGroupOrderFromHex(test_data_dir):
        # Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
        with open("./test_data/testData_GetGroupDegree", "r") as getGrpDegree_txt: #Test data are generated from https://svn.python.org/projects/external/openssl-0.9.8a/crypto/ec/ec_curve.c
            for x in getGrpDegree_txt:

                # Reading the line of the file as string and splitting into list
                nidID_Degree_Value = x.split(",")
                # Generate a Random EC Point with default NID ==> NID_secp256k1
                ec_pt_a = PyNakasendo.PyECPoint.PyECPoint(int(nidID_Degree_Value[0]))
                ec_pt_a.SetRandom()

                # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
                assert ec_pt_a.CheckOnCurve(), "Test failed"
                #EC Point Group Degree with supplied curve
                grpDegreeHex = ec_pt_a.GetECGroupDegree()

                # Verifying the actual value with the expected value.
                assert grpDegreeHex == int(nidID_Degree_Value[1]), "Test failed"

                #EC Point Group Order with supplied curve
                actual_value = ec_pt_a.GetECGroupOrder()
                assert actual_value.ToHex() == nidID_Degree_Value[2].rstrip("\n"), "Test failed"
