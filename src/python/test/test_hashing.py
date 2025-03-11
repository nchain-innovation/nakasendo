import pathlib
import ast
import unittest
from PyNakasendo import PyNakasendo

class MsgHash(unittest.TestCase):
    def test_sha256_file(self):
        # Reading test data from the file
         with open("./test_data/testData_MsgSHA256", "r") as msgHashFile_txt:

            for x in msgHashFile_txt.readlines():

                msg_Hash_value = x.split(",")
                # Generate SHA256 hash on a given input
                actual_Value = PyNakasendo.Utils.hash_sha256_str(msg_Hash_value[0])

                # Verifying the actual value with expected value
                assert actual_Value.hex() == msg_Hash_value[1].rstrip("\n"), "Test failed"


    def test_sha256_hex(self):

        input_str1 = "hello world"	
        expcted_str1 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

        input_str2 = ""
        expected_str2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        input_str3 = "Bitcoin"

        expected_str3 = "b4056df6691f8dc72e56302ddad345d65fead3ead9299609a826e2344eb63aa4"
                         
        # Generate SHA256 hash on a given input
        actual_Value1 = PyNakasendo.Utils.hash_sha256_str(input_str1)
        actual_Value2 = PyNakasendo.Utils.hash_sha256_str(input_str2)
        actual_Value3 = PyNakasendo.Utils.hash_sha256_str(input_str3) 

        # Verifying the actual value with expected value
        assert actual_Value1.hex() == expcted_str1, "Test failed"
        assert actual_Value2.hex() == expected_str2, "Test failed" 
        assert actual_Value3.hex() == expected_str3, "Test failed"

    def test_sha512_str(self):

        input_str1 = "hello world"	
        expcted_str1 = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"

        input_str2 = ""
        expected_str2 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        input_str3 = "Bitcoin"

        expected_str3 = "4645b9c1e070f2aca3e061222eb54ef4c9dbb3477cdd6faa0aaee844c61c3bc26123736723c5aab8ff0dc5298c9a8b2a5faa02ac7fd711329fe2c167c81ffa65"
                         
        # Generate SHA256 hash on a given input
        actual_Value1 = PyNakasendo.Utils.hash_sha512_str(input_str1)
        actual_Value2 = PyNakasendo.Utils.hash_sha512_str(input_str2)
        actual_Value3 = PyNakasendo.Utils.hash_sha512_str(input_str3) 

        # Verifying the actual value with expected value
        assert actual_Value1.hex() == expcted_str1, "Test failed"
        assert actual_Value2.hex() == expected_str2, "Test failed" 
        assert actual_Value3.hex() == expected_str3, "Test failed"

    def test_sha512_bytes(self):

        input_str1 = b"hello world"	
        expcted_str1 = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"

        input_str2 = b""
        expected_str2 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        input_str3 = b"Bitcoin"

        expected_str3 = "4645b9c1e070f2aca3e061222eb54ef4c9dbb3477cdd6faa0aaee844c61c3bc26123736723c5aab8ff0dc5298c9a8b2a5faa02ac7fd711329fe2c167c81ffa65"
                         
        # Generate SHA256 hash on a given input
        actual_Value1 = PyNakasendo.Utils.hash_sha512_bytes(input_str1)
        actual_Value2 = PyNakasendo.Utils.hash_sha512_bytes(input_str2)
        actual_Value3 = PyNakasendo.Utils.hash_sha512_bytes(input_str3) 

        # Verifying the actual value with expected value
        assert actual_Value1.hex() == expcted_str1, "Test failed"
        assert actual_Value2.hex() == expected_str2, "Test failed" 
        assert actual_Value3.hex() == expected_str3, "Test failed"


    def test_doublesha256_hex(self):

        input_str1 = b"hello world"	
        expcted_str1 = "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423"

        input_str2 = b""
        expected_str2 = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"

        input_str3 = b"Bitcoin"
        expected_str3 = "1ab3b6827ceeea24155245b11418dd6021d6f2d4e7193172f3f8dc03c650ef6f"
    
                         
        # Generate SHA256 hash on a given input
        actual_Value1 = PyNakasendo.Utils.double_sha256(input_str1)
        actual_Value2 = PyNakasendo.Utils.double_sha256(input_str2)
        actual_Value3 = PyNakasendo.Utils.double_sha256(input_str3) 

        # Verifying the actual value with expected value
        assert actual_Value1.hex() == expcted_str1, "Test failed"
        assert actual_Value2.hex() == expected_str2, "Test failed" 
        assert actual_Value3.hex() == expected_str3, "Test failed"

        
