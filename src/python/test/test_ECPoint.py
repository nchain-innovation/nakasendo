
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
            ec_pt = PyNakasendo.PyECPoint((curve_id))
            ec_pt.SetRandom()
            ec_ptr_hex  = ec_pt.ToHex()
  
            # Verifying the the length of actual value as 66
            assert len(ec_ptr_hex) == 66, "Test failed"

    def test_CheckOnCurve(self):
    # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt = PyNakasendo.PyECPoint(714)
            ec_pt.SetRandom()
            assert ec_pt.CheckOnCurve(), "test failed"

    def test_GetAffineCoOrdinates(self):
    # Generating Random EC
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt = PyNakasendo.PyECPoint(714)
            ec_pt.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt.CheckOnCurve(), "test failed"
            x_axis, y_axis = ec_pt.GetAffineCoords()
            assert len(x_axis) == 62 or len(x_axis) == 64, "Test failed"


    def test_GetAffineCoOrdinatesOnCurve(self):
    # Generating Random EC Points
        for x in range(100):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt = PyNakasendo.PyECPoint(714)
            ec_pt.SetRandom()
            # Check if the point is on the curve with t
            assert ec_pt.CheckOnCurve(), "test failed"
            # EC Point GetAffineCoOrdinates_GFp with supplied curve
            x_axis, y_axis = ec_pt.GetAffineCoords()
            assert len(x_axis) == 62 or len(x_axis) == 64, "Test failed"

    def test_AddECFromHex(test_data_dir):
    #Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
        with open("./test_data/testData_AddECFromHex", "r") as addEChex_txt:
            for x in addEChex_txt:
                hexNumber = x.split(",")
            ec_pt_a = PyNakasendo.PyECPoint(714)
            ec_pt_a.FromHex(hexNumber[0])
            ec_pt_b = PyNakasendo.PyECPoint(714)
            ec_pt_b.FromHex(hexNumber[1])
            assert ec_pt_a.CheckOnCurve(), "test failed"
            assert ec_pt_b.CheckOnCurve(), "test failed"

            ec_pt_sum = ec_pt_a + ec_pt_b
            assert ec_pt_sum.CheckOnCurve(), "test failed"

            # Verifying the actual value with expected value
            assert ec_pt_sum.ToHex() == hexNumber[2].rstrip("\n"), "Test failed"

    def test_MultiplyScalarM():
    # Generating Random EC Points
        for x in range(100):

            # Generate a Random EC Point with default NID ==> NID_secp256k1
            ec_pt_a = PyNakasendo.PyECPoint(714)
            ec_pt_a.SetRandom()
            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt_a.CheckOnCurve()
            # create a bignumber
            val1 = PyNakasendo.PyBigNumber()
            val1.generateRandHex()

            
            x = PyECPoint.GenerateRandomEC(0, hex, True )
            y = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(x, 0, hex) and PyECPoint.CheckOnCurve(y, 0, hex ), "Test failed"

        # EC Point Scalar multiply with default NID => NID_secp256k1
        actual_value = PyECPoint.MultiplyScalarM(x, y, 0, hex, True )

        # Verifying the actual value with expected value
        assert len(actual_value) == 66, "Test failed"

'''


def test_AddECFromHex(test_data_dir):

    #Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
    with open(test_data_dir/"testData_AddECFromHex", "r") as addEChex_txt:
        for x in addEChex_txt:

            hexNumber = x.split(",")

            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert PyECPoint.CheckOnCurve(hexNumber[0], 0, hex ), "Test failed"

            # Add two ECPoints in hex with the default NID ==> NID_secp256k1
            actual_value = PyECPoint.Add(hexNumber[0], hexNumber[1], 0, hex, True)

            # Verifying the actual value with expected value
            assert actual_value == hexNumber[2].rstrip("\n") and len(actual_value) == 66, "Test failed"

def test_AddECFromHexWithCurveID(test_data_dir):

    #Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
    with open(test_data_dir/"testData_AddECFromHex", "r") as addEChex_txt:
        for x in addEChex_txt:

            hexNumber = x.split(",")

            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert PyECPoint.CheckOnCurve(hexNumber[0], 0, hex ), "Test failed"

            # Add two ECPoints in hex with the supplied curve IDs
            actual_value = PyECPoint.Add(hexNumber[0], hexNumber[1], nid_Id, hex, True)

            # Verifying the actual value with expected value
            assert actual_value == hexNumber[2].rstrip("\n") and len(actual_value) == 66, "Test failed"



def test_MultiplyScalarMN():

    # Generating Random EC Points
    for x in range(100):
        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

        #Generate a Random Big number M and N using BigNumberAPIs
        bigNumbM = PyBigNumbers.GenerateRandDec(257)
        bigNumbN = PyBigNumbers.GenerateRandDec(128)

        # EC Point Scalar multiply with default NID => NID_secp256k1
        actual_value = PyECPoint.MultiplyScalarMN(ecPoint_value, bigNumbM, bigNumbN, 0, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_MultiplyScalarMOnCurve():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        x = PyECPoint.GenerateRandomEC(0, hex, True )
        y = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(x, 0, hex) and PyECPoint.CheckOnCurve(y, 0, hex  ) , "Test failed"

        # EC Point Scalar multiply on curve with supplied ID
        actual_value = PyECPoint.MultiplyScalarM(x, y, nid_Id, hex, True )

        # Verifying the actual value with expected value
        assert len(actual_value) == 66, "Test failed"

def test_MultiplyScalarMNOnCurve():

    # Generating Random EC Points
    for x in range(100):
        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex), "Test failed"

        #Generate a Random Big number M and N using BigNumberAPIs
        bigNumbM = PyBigNumbers.GenerateRandDec(257)
        bigNumbN = PyBigNumbers.GenerateRandDec(128)

        # EC Point Scalar multiply with supplied curve ID
        actual_value = PyECPoint.MultiplyScalarMN(ecPoint_value, bigNumbM, bigNumbN, nid_Id, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_CheckInfinityFromHex():

    # Generating Random EC Points
    for x in range(100):
        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC( 0, hex, True  )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ) , "Test failed"

        # Check if the given point is at infinity with default NID ==> NID_secp256k1
        actual_value = PyECPoint.GenerateEC(ecPoint_value, 0, hex, True)
        assert PyECPoint.CheckInfinity(actual_value, 0, hex ) is False, "Test failed"

def test_CheckInfinityFromHexCurve():

    # Generating Random EC Points
    for x in range(100):
        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC( 0, hex, True  )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

        # Check if the given point is at infinity on the given curve ID
        actual_value = PyECPoint.GenerateEC(ecPoint_value, 0, hex, True )
        assert PyECPoint.CheckInfinity(actual_value,  nid_Id, hex) is False, "Test failed"

def test_CheckOnCurveFromHexOnCurve():

    # Generating Random EC Points
    for x in range(100):
        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC( 0, hex, True )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

        # Check if the given point is at infinity on the given curve ID
        actual_value = PyECPoint.GenerateEC(ecPoint_value, 0, hex, True )
        assert PyECPoint.CheckInfinity(actual_value,  nid_Id, hex) is False, "Test failed"

        #Check if the point is on the curve with supplied curve ID
        assert PyECPoint.CheckOnCurve(actual_value,  nid_Id, hex ) is True, "Test failed"

def test_CompareECPoint():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )
        ecPoint_value2 = PyECPoint.GenerateRandomEC(0, hex, True )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"
        assert PyECPoint.CheckOnCurve(ecPoint_value2, 0, hex ), "Test failed"

        #Compare two given ECPoints
        assert PyECPoint.Compare(ecPoint_value, ecPoint_value2, 0, hex) is False, "Test failed"

def test_CompareCurveECPoint():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )
        ecPoint_value2 = PyECPoint.GenerateRandomEC(0, hex, True )
        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"
        assert PyECPoint.CheckOnCurve(ecPoint_value2, 0, hex ), "Test failed"

        #Compare two given ECPoints
        assert PyECPoint.Compare(ecPoint_value, ecPoint_value2, 0, hex ) is False, "Test failed"

        #Compare two given ECPoints with a Curve ID
        assert PyECPoint.Compare(ecPoint_value, ecPoint_value2, nid_Id, hex ) is False, "Test failed"

def test_DoubleFromHex():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex  ), "Test failed"

        #Double the ECPoint in hex with the default NID ==> NID_secp256k1
        actual_value = PyECPoint.Double(ecPoint_value, 0, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_DoubleFromHexCurve():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

        #Double the ECPoint in hex with the default NID ==> NID_secp256k1
        doubleECPoint_value = PyECPoint.Double(ecPoint_value, 0, hex, True)

        #Double the ECPoint in hex with the given curve ID
        actual_value = PyECPoint.Double(doubleECPoint_value, nid_Id, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_InvertFromHex():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex  ), "Test failed"

        #Invert the ECPoint in hex with the default NID ==> NID_secp256k1
        actual_value = PyECPoint.Invert(ecPoint_value, 0, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_InvertFromHexCurve():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

        #Double the ECPoint in hex with the default NID ==> NID_secp256k1
        doubleECPoint_value = PyECPoint.Invert(ecPoint_value, 0, hex, True)

        #Double the ECPoint in hex with the given curve ID
        actual_value = PyECPoint.Invert(doubleECPoint_value, nid_Id, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_GetGenerator():

    # Generating Random EC Points
    for x in range(100):

        # Generate a Random EC Point with default NID ==> NID_secp256k1
        ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

        #EC Point Generator with the supplied curve ID
        actual_value = PyECPoint.GetGenerator(ecPoint_value, nid_Id, hex, True)

        # Verifying the the length of actual value as 66
        assert len(actual_value) == 66, "Test failed"

def test_GetGroupDegreeFromHex(test_data_dir):

    # Generate a Random EC Point with default NID ==> NID_secp256k1
    ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

    # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
    assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

    # EC Point Generator with the supplied curve ID
    generator_Point = PyECPoint.GetGenerator(ecPoint_value, nid_Id, hex, True)

    # Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
    with open(test_data_dir/"testData_GetGroupDegree", "r") as getGrpDegree_txt:#Test data are generated from https://svn.python.org/projects/external/openssl-0.9.8a/crypto/ec/ec_curve.c
        for x in getGrpDegree_txt:

            # Reading the line of the file as string and splitting into list
            nidID_Degree_Value = x.split(",")

            #EC Point Group Degree with supplied curve
            actual_value = PyECPoint.GetGroupDegree(generator_Point, int(nidID_Degree_Value[0]), hex)

            # Verifying the actual value with the expected value.
            assert actual_value == int(nidID_Degree_Value[1]), "Test failed"

def test_GetGroupOrderFromHex(test_data_dir):

    # Generate a Random EC Point with default NID ==> NID_secp256k1
    ecPoint_value = PyECPoint.GenerateRandomEC(0, hex, True )

    # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
    assert PyECPoint.CheckOnCurve(ecPoint_value, 0, hex ), "Test failed"

    # EC Point Generator with the supplied curve ID
    generator_Point = PyECPoint.GetGenerator(ecPoint_value, nid_Id, hex, True)

    # Reading a Random generated EC Point with default NID ==> NID_secp256k1 from file
    with open(test_data_dir/"testData_GetGroupDegree", "r") as getGrpDegree_txt: #Test data are generated from https://svn.python.org/projects/external/openssl-0.9.8a/crypto/ec/ec_curve.c
        for x in getGrpDegree_txt:

            # Reading the line of the file as string and splitting into list
            nidID_Degree_Value = x.split(",")

            #EC Point Group Degree with supplied curve
            grpDegreeHex = PyECPoint.GetGroupDegree(generator_Point, int(nidID_Degree_Value[0]), hex)

            # Verifying the actual value with the expected value.
            assert grpDegreeHex == int(nidID_Degree_Value[1]), "Test failed"

            #EC Point Group Order with supplied curve
            actual_value = PyECPoint.GetGroupOrder(generator_Point, int(nidID_Degree_Value[0]), hex)
            assert actual_value == nidID_Degree_Value[2].rstrip("\n"), "Test failed"
'''
