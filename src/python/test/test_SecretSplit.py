import unittest
from PyNakasendo import PyNakasendo
from random import randint

maxshares = 100
privKeyPEMHeader = "BEGIN EC PRIVATE KEY"


class SecretSplitTests(unittest.TestCase):
    def test_KeySplit(self):
        for x in range(10):

            #Randomly generate two digit number that ranges from 3 to 100
            #threshold = randint(3, 100)
            threshold: int = 20
            maxshares: int = 100
            degree: int = threshold -1
            curve_id: int = 714
            # mod 
            mod = PyNakasendo.PyBigNumber.PyBigNumber()
            mod.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            # Generate pair of keys in pem format
            privKey = PyNakasendo.PyAsymKey.PyAsymKey(curve_id)

            poly = PyNakasendo.PyPolynomial(degree, mod, privKey.exportPrivateKey())
            #assert privKeyPEMHeader in privKey, "Test failed"

            # Split a private key into a given number of shares
            splitKeyList = PyNakasendo.PySecretShare.make_shared_secret(poly, threshold, maxshares)
            assert len(splitKeyList) == maxshares, "Test failed"

    def test_RestoreKey(self):

        for x in range(10):

            thresholdList = []
            # Randomly generate two digit number that ranges from 3 to 100
            threshold = randint(3, 100)
            curve_id:int = 714
            degree: int = threshold-1
            maxshares: int = 100
            # mod 
            mod = PyNakasendo.PyBigNumber.PyBigNumber()
            mod.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            # Generate pair of keys in pem format
            privKey = PyNakasendo.PyAsymKey.PyAsymKey(curve_id)

            poly = PyNakasendo.PyPolynomial(degree, mod, privKey.exportPrivateKey())
            #assert privKeyPEMHeader in privKey, "Test failed"

            # Split a private key into a given number of shares
            splitKeyList = PyNakasendo.PySecretShare.make_shared_secret(poly, threshold, maxshares)

            assert len(splitKeyList) == maxshares, "Test failed"

            for i in range(threshold):
                thresholdList.append(splitKeyList[i])

            assert len(thresholdList) == threshold, "Test failed"

            recovered_secret: PyNakasendo.BigNumber = PyNakasendo.PySecretShare.RecoverSecret(thresholdList, mod);
            recovered_pri_key = PyNakasendo.PyAsymKey.FromBigNumber(recovered_secret)
            assert recovered_pri_key.exportPrivateKey().ToHex() == privKey.exportPrivateKey().ToHex(), "Test Failed"
            # convert list to String
            #thresholdString = ';'.join(thresholdList)

            # Restore a private key from a given number of shares
            #restorePubKey, restorePrivKey = PyAsymKey.RestoreKey(thresholdString, curve_id)
            #assert restorePrivKey == privKey, "Test failed"
'''
def test_ImportKeyFromPEM():

    for x in range(10):
        curve_id:int = 714
        # Generate pair of keys in pem format
        pubKey, privKey = PyAsymKey.GenerateKeyPairPEM(curve_id)
        assert privKeyPEMHeader in privKey, "Test failed"

        # Imports a key from a PEM format
        pubValue, priValue = PyAsymKey.ImportFromPem(privKey, curve_id)
        assert priValue == privKey, "Test failed"
        assert pubValue == pubKey, "Test failed"


def test_KeySplit():

    for x in range(10):

        #Randomly generate two digit number that ranges from 3 to 100
        threshold = randint(3, 100)
        curve_id:int = 714
        # Generate pair of keys in pem format
        pubKey, privKey = PyAsymKey.GenerateKeyPairPEM(curve_id)
        assert privKeyPEMHeader in privKey, "Test failed"

        # Split a private key into a given number of shares
        splitKeyList = PyAsymKey.SplitKey(privKey, threshold, maxshares, curve_id)
        assert len(splitKeyList) == maxshares, "Test failed"


def test_RestoreKey():

    for x in range(10):

        thresholdList = []
        # Randomly generate two digit number that ranges from 3 to 100
        threshold = randint(3, 100)
        curve_id:int = 714
        # Generate pair of keys in pem format
        pubKey, privKey = PyAsymKey.GenerateKeyPairPEM(curve_id)
        assert privKeyPEMHeader in privKey, "Test failed"

        # Split a private key into a given number of shares
        splitKeyList = PyAsymKey.SplitKey(privKey, threshold, maxshares, curve_id)
        assert len(splitKeyList) == maxshares, "Test failed"

        for i in range(threshold):

            thresholdList.append(splitKeyList[i])

        assert len(thresholdList) == threshold, "Test failed"

        # convert list to String
        thresholdString = ';'.join(thresholdList)

        # Restore a private key from a given number of shares
        restorePubKey, restorePrivKey = PyAsymKey.RestoreKey(thresholdString, curve_id)
        assert restorePrivKey == privKey, "Test failed"


def test_ImportSplitRestoreKey():

    for x in range(10):

        thresholdList = []
        # Randomly generate two digit number that ranges from 3 to 100
        threshold = randint(3, 100)
        curve_id:int = 714
        # Generate pair of keys in pem format
        pubKey, privKey = PyAsymKey.GenerateKeyPairPEM(curve_id)
        assert privKeyPEMHeader in privKey, "Test failed"

        # Imports a key from a PEM format
        pubValue, priValue = PyAsymKey.ImportFromPem(privKey,curve_id)
        assert priValue == privKey, "Test failed"
        assert pubValue == pubKey, "Test failed"

        # Split a private key into a given number of shares
        splitKeyList = PyAsymKey.SplitKey(privKey, threshold, maxshares,curve_id)
        assert len(splitKeyList) == maxshares, "Test failed"

        for i in range(threshold):

            thresholdList.append(splitKeyList[i])

        assert len(thresholdList) == threshold, "Test failed"

        # convert list to String
        thresholdString = ';'.join(thresholdList)

        # Restore a private key from a given number of shares
        restorePubKey, restorePrivKey = PyAsymKey.RestoreKey(thresholdString,curve_id)
        assert restorePrivKey == privKey, "Test failed"


def test_ThresholdEqualMaxShareTestcase():

    thresholdList = []
    #Randomly generate two digit number that ranges from 3 to 100
    threshold = 100
    curve_id:int = 714
    # Generate pair of keys in pem format
    pubKey, privKey = PyAsymKey.GenerateKeyPairPEM(curve_id)
    assert privKeyPEMHeader in privKey, "Test failed"

    # Split a private key into a given number of shares
    splitKeyList = PyAsymKey.SplitKey(privKey, threshold, maxshares,curve_id)
    assert len(splitKeyList) == maxshares, "Test failed"

    for i in range(threshold):

        thresholdList.append(splitKeyList[i])

    assert len(thresholdList) == threshold, "Test failed"

    # convert list to String
    thresholdString = ';'.join(thresholdList)

    # Restore a private key from a given number of shares
    restorePubKey, restorePrivKey = PyAsymKey.RestoreKey(thresholdString,curve_id)
    assert restorePrivKey == privKey, "Test failed"
'''