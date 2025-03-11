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

'''

def test_Sign_Verification():

    msg = 'Hello, I am a message, sign me'
    for x in range(100):
        # Generate pair of keys in PEM format
        curveid: int = 714
        pubKey, priKey = PyAsymKey.GenerateKeyPairPEM(curveid)

        # Sign message with private Key
        rSig, sSig = PyAsymKey.Sign(msg, priKey, curveid)

        # the verification needs to know where curve to verufy on
        # Verify message's signature with public key
        verify_ok = PyAsymKey.Verify(msg, pubKey, rSig, sSig, curveid)
        assert verify_ok, "Test failed"

def test_ShareSecret():

    for x in range(100):
        # Generate keys for alice and bob
        curveid: int = 714
        alice_pubKeyPEM, alice_privKeyPEM = PyAsymKey.GenerateKeyPairPEM(curveid)
        bob_pubKeyPEM, bob_privKeyPEM = PyAsymKey.GenerateKeyPairPEM(curveid)

        #Calculate shared secret from my private key and their public key
        secret_share_from_alice = PyAsymKey.ShareSecret(alice_privKeyPEM, bob_pubKeyPEM, curveid)
        secret_share_from_bob = PyAsymKey.ShareSecret(bob_privKeyPEM, alice_pubKeyPEM, curveid)
        assert secret_share_from_alice==secret_share_from_bob, "Test failed"

def test_KeyDerive():

    additive_msg = 'I am a random message used for key derivation'
    for x in range(100):
        # Generate keys for alice and bob
        curveid: int = 714
        alice_pubKeyPEM, alice_privKeyPEM = PyAsymKey.GenerateKeyPairPEM(curveid)
        bob_pubKeyPEM, bob_privKeyPEM = PyAsymKey.GenerateKeyPairPEM(curveid)

        # Derive public key from a given public key and a additive message
        alice_derived_pub = PyAsymKey.DerivePublic(alice_pubKeyPEM, additive_msg)
        bob_derived_pub = PyAsymKey.DerivePublic(bob_pubKeyPEM, additive_msg)

        # Derive pirvate key from a given private key and a additive message
        alice_derived_private = PyAsymKey.DerivePrivate(alice_privKeyPEM, additive_msg, curveid)
        bob_derived_private = PyAsymKey.DerivePrivate(bob_privKeyPEM, additive_msg, curveid)

        # Export public key PEM given the private key PEM
        calc_alice_derived_pub = PyAsymKey.ExportPublicPEM(alice_derived_private)
        calc_bob_derived_pub = PyAsymKey.ExportPublicPEM(bob_derived_private)
        assert calc_alice_derived_pub == alice_derived_pub, "Test failed"
        assert calc_bob_derived_pub == bob_derived_pub, "Test failed"
'''