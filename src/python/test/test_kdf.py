import unittest
import binascii
from PyNakasendo import PyNakasendo

class kdfTests(unittest.TestCase):
    def test_GenerateNonce(self):
        nonce: str = PyNakasendo.Utils.GenerateNonce()
        # the string reprensentation is 32 characters long, it's 16-bytes
        assert len(nonce) == 32, "Test Failed"

    def test_pw_generation(self):
        password: str = "testpassword"
        nonce: str =  PyNakasendo.Utils.GenerateNonce()

        key1: str = PyNakasendo.Utils.GenerateKey(password, nonce)
        key2: str = PyNakasendo.Utils.GenerateKey(password, nonce)

        assert key1 == key2, "Test Failed .. key1 should be equal to key2"

    def test_pw_generation_unequal(self):
        password: str = "testpassword"
        nonce1: str = PyNakasendo.Utils.GenerateNonce()
        nonce2: str = PyNakasendo.Utils.GenerateNonce()

        key1: str = PyNakasendo.Utils.GenerateKey(password, nonce1)
        key2: str = PyNakasendo.Utils.GenerateKey(password, nonce2)

        assert key1 != key2, "Test Failed .. key1 should not be equal to key2"

    def test_pw_generation_unequal(self):
        password: str = "testpassword"
        nonce1: str = PyNakasendo.Utils.GenerateNonce()
        nonce2: str = PyNakasendo.Utils.GenerateNonce()

        key1: str = PyNakasendo.Utils.GenerateKey(password, nonce1)
        key2: str = PyNakasendo.Utils.GenerateKey(password, nonce2)

        assert key1 != key2, "Test Failed .. key1 should not be equal to key2"

    def test_expected_password(self):
        password: str = "password123"
        nonce: str = "random_salt"

        # derived from cryptography python module (see simple_test.py)
        expected_bytes_str = "9a7a70fec17daa9d2a76f54bfe93762618df014c17782b12958aba265136c98e"
        key1: str = PyNakasendo.Utils.GenerateKey(password, nonce)
        assert key1 == expected_bytes_str, "test failed .. expected keys not equal"