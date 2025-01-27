import unittest
from PyNakasendo import PyNakasendo

class BigNumberTests(unittest.TestCase):
    def test_one(self):
        val = PyNakasendo.PyBigNumber()
        val.One()
        assert (val.ToHex() == "01")


    def test_AddFromDecWithBigNumApi(self):
        # Reading test data from the file
        with open("./test_data/testData_AddDec", "r") as addDec_txt:
            for x in addDec_txt:

                decNumber = x.split()
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                # Add too big numbers of arbitrary precision in dec
                val3 = val1 + val2
                #Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[2], "Test failed"

    def test_AddFromHexWithBigNumApi(self):
    # Reading test data from the file
        with open("./test_data/testData_AddHex", "r") as addHex_txt:
            for x in addHex_txt:
                hexNumber = x.split()
                # Add too big numbers of arbitrary precision in Hex
                val1 = PyNakasendo.PyBigNumber()
                val1.FromHex(hexNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromHex(hexNumber[1])
                val3 = val1 + val2
                #Verifying the actual value with expected value
                assert val3.ToHex().upper() == hexNumber[2].upper(), "Test failed"

    def test_SubFromDecWithBigNumApi(self):
        # Reading test data from the file
        with open("./test_data/testData_SubDec", "r") as subDec_txt:
            for x in subDec_txt:
                decNumber = x.split()
                val1= PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = val1 - val2
                #Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[2], "Test failed"

    def test_SubFromHexWithBigNumApi(self):
        # Reading test data from the file
        with open("./test_data/testData_SubHex", "r") as subHex_txt:
            for x in subHex_txt:
                hexNumber = x.split()
                val1 = PyNakasendo.PyBigNumber()
                val1.FromHex(hexNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromHex(hexNumber[1])
                val3 = val1 - val2
                #Verifying the actual value with expected value
            assert val3.ToHex().upper() == hexNumber[2].upper(), "Test failed"

    def test_GenRandDec(self):
    # Reading test data from the file
        with open("./test_data/testData_GenBigNum", "r") as genDec_txt:
            for x in genDec_txt.readlines():
                decNumber = int(x)
                # Generate Random Number of arbitrary precision in dec
                val1 = PyNakasendo.PyBigNumber()
                result = val1.GenerateRandDec(512)
                #Verifying the actual value as a string and not negative value
                assert type(result) is str and result != "-1", "Test failed"

    def test_GenRandHex(self):
    # Reading test data from the file
        with open("./test_data/testData_GenBigNum", "r") as genHex_txt:
            for x in genHex_txt.readlines():
                decNumber = int(x)
                # Generate Random Number of arbitrary precision in dec
                val1 = PyNakasendo.PyBigNumber()
                str_val = val1.GenerateRandHex(512)
                #Verifying the actual value as a string and not negative value
                assert type(str_val) is str and str_val != "-1", "Test failed"

    #def test_genRandDecWithSeed(self):
    # Reading test data from the file
    #    with open(test_data_dir/"testData_SeedDec", "r") as seedDec_txt:
    #        for x in seedDec_txt:
    #            decNumber = x.split()
                # Generate Random Number of arbitrary precision in Dec with seed (specified as a string)
    #            actual_Value = PyBigNumbers.GenerateRandDecWithSeed(decNumber[0], int(decNumber[1]))
                #Verifying the actual value as a string with no negative sign
    #            assert type(actual_Value) is str and actual_Value != "-1", "Test failed"

    #def test_genRandHexWithSeed(test_data_dir):
    # Reading test data from the file
    #    with open(test_data_dir/"testData_SeedDec", "r") as seedHex_txt:
    #        for x in seedHex_txt:
    #            decNumber = x.split()
                # Generate Random Number of arbitrary precision in hex with seed (specified as a string)
    #            actual_Value = PyBigNumbers.GenerateRandHexWithSeed(decNumber[0], int(decNumber[1]))
                #Verifying the actual value as a string with no negative sign
    #            assert type(actual_Value) is str and actual_Value != "-1", "Test failed"

    #def test_IsPrimeDec(self):
    # Reading test data from the file
    #    with open("./test_data/testData_PrimeDec", "r") as primeDec_txt:
    #        for x in primeDec_txt:
    #            decNumber = x.split(",")
    #            val1 = PyNakasendo.PyBigNumnber()
    #            val1.FromDec(decNumber[0].rstrip("\n"))
                # Check if Dec big number is a prime
    #            actual_Value = PyBigNumbers.isPrimeDec(decNumber[0].rstrip("\n"))
                # Verifying the actual value with expected value
    #            assert actual_Value == int(decNumber[1]), "Test failed"

    #def test_IsPrimeHex(self):
    # Reading test data from the file
    #    with open("./test_data/testData_PrimeDec", "r") as primeHex_txt:
    #        for x in primeHex_txt:
    #            decNumber = x.split(",")
                #converting decimal to hex-decimal
    #            j = int(decNumber[0])
    #            hex_Value = hex(j).lstrip("0x")
                # Check if hex big number is a prime
    #            actual_Value = PyBigNumbers.isPrimeHex(str(hex_Value))
                # Verifying the actual value with expected value
    #            assert actual_Value == int(decNumber[1]), "Test failed"



    def test_MultiplyDec(test_data_dir):
    # Reading test data from the file
        with open("./test_data/testData_MultiplyDec", "r") as multiplyDec_txt:
            for x in multiplyDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = val1 * val2
                # Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[2].rstrip("\n"), "Test failed"

    def test_MultiplyHex(test_data_dir):
    # Reading test data from the file
        with open("./test_data/testData_MultiplyDec", "r") as multiplyHex_txt:
            for x in multiplyHex_txt:
                decNumber = x.split(",")
                #converting decimal to hex-decimal
                i = int(decNumber[0])
                j = int(decNumber[1])
                k = int(decNumber[2].rstrip("\n"))
              

                val_i = PyNakasendo.PyBigNumber()
                val_j = PyNakasendo.PyBigNumber()
                val_i.FromDec(decNumber[0])
                val_j.FromDec(decNumber[1])
                val_res = val_i * val_j
                assert int(val_res.ToHex(), 16) == k, "Test failed"

    def test_LeftShiftDec(self):
    # Reading test data from the file
        with open("./test_data/testData_LeftRightShiftDec", "r") as leftDec_txt:
            for x in leftDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                # leftshit bitwise operation that moves bits of right big number to the left by left big number value in dec
                val3 = val1 << val2
                # Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[2].rstrip("\n"), "Test failed"

    def test_RightShiftDec(self):
    # Reading test data from the file
        with open("./test_data/testData_LeftRightShiftDec", "r") as rightDec_txt:
            for x in rightDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[2])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                # rightshift bitwise operation that moves bits of right big number to the right by left big number value in dec
                val3 = val1 >> val2
                # Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[0], "Test failed"


    def test_DivideDec(self):
    # Reading test data from the file
        with open("./test_data/testData_DivideDec", "r") as divideDec_txt:
            for x in divideDec_txt:
                decNumber = x.split(",")
                # Divide two big numbers of arbitrary precision in dec
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = val1 / val2
                # Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[2].rstrip("\n"), "Test failed"


    def test_ModuloDec(self):
    # Reading test data from the file
        with open("./test_data/testData_ModuloDec", "r") as moduloDec_txt:
            for x in moduloDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = val1 % val2
                # Verifying the actual value with expected value
                assert val3.ToDec() == decNumber[2].rstrip("\n"), "Test failed"


    def test_AddModDec(self):
    # Reading test data from the file
        with open("./test_data/testData_AddModDec", "r") as addModDec_txt:
            for x in addModDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = PyNakasendo.PyBigNumber()
                val3.FromDec(decNumber[2])
                val4 = PyNakasendo.PyBigNumber.Add_mod(val1, val2, val3)
                # Verifying the actual value with expected value
                assert val4.ToDec() == decNumber[3].rstrip("\n"), "Test failed"

    def test_SubModDec(self):
    # Reading test data from the file
        with open("./test_data/testData_SubModDec", "r") as subModDec_txt:
            for x in subModDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = PyNakasendo.PyBigNumber()
                val3.FromDec(decNumber[2])
                val4 = PyNakasendo.PyBigNumber.Sub_mod(val1, val2, val3)
                # Verifying the actual value with expected value
                assert val4.ToDec() == decNumber[3].rstrip("\n"), "Test failed"


    def test_MulModDec(self):

    # Reading test data from the file
        with open("./test_data/testData_MulModDec", "r") as mulModDec_txt:
            for x in mulModDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = PyNakasendo.PyBigNumber()
                val3.FromDec(decNumber[2])
                val4 = PyNakasendo.PyBigNumber.Mul_mod(val1, val2, val3)
                # Multiply modulo of big numbers of arbitrary precision in dec
                assert val4.ToDec() == decNumber[3].rstrip("\n"), "Test failed"


    def test_DivModDec(self):
    #Reading test data from the file
        with open("./test_data/testData_DivModDec", "r") as divModDec_txt:
            for x in divModDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])
                val3 = PyNakasendo.PyBigNumber()
                val3.FromDec(decNumber[2])
                #Divide modulo of big numbers of arbitrary precision in dec
                val4 = PyNakasendo.PyBigNumber.Div_mod(val1, val2, val3)

                #verifying the actual value with the expected value
                assert val4.ToDec() == decNumber[3].rstrip("\n"), "Test failed"


    def test_InvModDec(test_data_dir):
    #Reading test data from the file
        with open("./test_data/testData_InvModDec", "r") as invModDec_txt:
            for x in invModDec_txt:
                decNumber = x.split(",")
                val1 = PyNakasendo.PyBigNumber()
                val1.FromDec(decNumber[0])
                val2 = PyNakasendo.PyBigNumber()
                val2.FromDec(decNumber[1])    
                #Inverse modulo of big numbers of arbitrary precision in dec
                actual_value = PyNakasendo.PyBigNumber.Inv_mod(val1,val2)
                #verifying the actual value with the expected value
                assert actual_value.ToDec() == decNumber[2].rstrip("\n"), "Test failed"


if __name__ == "__main__":
    unittest.main()
