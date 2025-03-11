import unittest
from PyNakasendo import PyNakasendo

class AsymKeyTests(unittest.TestCase):
    def test_GenerateKey(self):
        for x in range(100):
            # Generate pair of keys in hex format
            asym_key = PyNakasendo.PyAsymKey.PyAsymKey()
            assert asym_key.is_valid(), "Test failed"

    def test_GenerateKeyPem(self):
        privKeyPEMHeader = "BEGIN PRIVATE KEY"
        for x in range(100):
            asym_key = PyNakasendo.PyAsymKey.PyAsymKey()
            pem_priv_key = asym_key.exportPrivateKeyPEM()
            assert privKeyPEMHeader in pem_priv_key, "Test failed"

    def test_ExportPublicKeyPEM(self):

        for x in range(100):
            # Generate pair of keys in pem format
            asym_key = PyNakasendo.PyAsymKey.PyAsymKey()
            prikey = asym_key.exportPrivateKeyPEM()
            asym_key_rebuilt = PyNakasendo.PyAsymKey.FromPemStr(prikey)
            

            # Calculated public key should match the generated one
            assert asym_key.exportPublicKey() == asym_key_rebuilt.exportPublicKey(), "Test failed"

    def test_Sign_Verication(self):
        msg = "Hello, I am a message, sign me"
        for x in range(100):
            asym_key = PyNakasendo.PyAsymKey.PyAsymKey()
            rSig, sSig = asym_key.sign(msg)
            assert PyNakasendo.PyAsymKey.verify(msg, asym_key.exportPublicKeyPEM(), (rSig,sSig)), "Test failed"

    def test_ShareSecret(self):

        for x in range(100):
            # Generate keys for alice and bob
            curveid: int = 714
            alice_key = PyNakasendo.PyAsymKey.PyAsymKey()
            bob_key = PyNakasendo.PyAsymKey.PyAsymKey()


            #Calculate shared secret from my private key and their public key
            secret_share_from_alice = alice_key.DH_SharedSecret(bob_key.exportPublicKeyPEM())
            secret_share_from_bob = bob_key.DH_SharedSecret(alice_key.exportPublicKeyPEM())
            assert secret_share_from_alice==secret_share_from_bob, "Test failed"


    def test_KeyDerive(self):

        additive_msg = 'I am a random message used for key derivation'
        for x in range(100):
            # Generate keys for alice and bob
            curveid: int = 714
            alice_key = PyNakasendo.PyAsymKey.PyAsymKey()
            bob_key = PyNakasendo.PyAsymKey.PyAsymKey()

            # Derive pirvate key from a given private key and a additive message
            alice_derived_key = PyNakasendo.PyAsymKey.derive_new_key(alice_key, additive_msg)
            bob_derived_key = PyNakasendo.PyAsymKey.derive_new_key(bob_key, additive_msg)

            assert alice_derived_key.is_valid(), "Test failed"
            assert bob_derived_key.is_valid(), "Test Failed"
