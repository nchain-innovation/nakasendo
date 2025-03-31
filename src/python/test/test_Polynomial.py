
import unittest
from PyNakasendo import PyNakasendo
from random import randint


class PolynomialTests(unittest.TestCase):
    def test_InitFromListCoefficient(self):

        # the polynomial of f = 3x^4 + 13x^3 + 5x^2 + 2x + 1
        # and working with the modulo equal 17 and the degree equal 4
        # evaluate the polynomial at x equal 2.
        # the expression will f(2) = ((3 x 2^4) + (13 x 2^3) + (5 x 2^2) + (2 x 2) + 1) mod 17 = 7

        val1 = PyNakasendo.PyBigNumber.PyIntToBigNumber(1)
        val2 = PyNakasendo.PyBigNumber.PyIntToBigNumber(2)
        val3 = PyNakasendo.PyBigNumber.PyIntToBigNumber(5)
        val4 = PyNakasendo.PyBigNumber.PyIntToBigNumber(13)
        val5 = PyNakasendo.PyBigNumber.PyIntToBigNumber(3)

        coefficients = [val1, val2, val3, val4, val5]
        mod = PyNakasendo.PyBigNumber.PyIntToBigNumber(17)


        #expcted value is 7 given this polynomial, mod & x value
        actualValue = PyNakasendo.PyBigNumber.PyIntToBigNumber(7)

        # create a Polynomial from a list of coefficients
        poly = PyNakasendo.PyPolynomial(coefficients, mod)
        val_x = PyNakasendo.PyBigNumber.PyIntToBigNumber(2)
        polynomialFX = poly(val_x)
        assert polynomialFX == actualValue


    def test_InitFromListHex(self):

        hex_value = 0
        for x in range(10, 15):

            fx = PyNakasendo.PyBigNumber.GenerateRand(256)
            modulo = PyNakasendo.PyBigNumber.GenerateRandPrime(100)
            listCoefficients = []

            for i in range(x):
                # Generate random coefficients for the polynomial
                listCoefficients.append(PyNakasendo.PyBigNumber.GenerateRand(256))

            # create a Polynomial from a list of coefficients
            poly = PyNakasendo.PyPolynomial(listCoefficients, modulo)
            polynomialFX = poly(fx)


    def test_LGECInterpolatorFull(self):

        modulo = PyNakasendo.PyBigNumber.GenerateRandPrime(1000)
        xValue = PyNakasendo.PyBigNumber.GenerateRand(1000)
        listTupleObj = []
        dec = False

        # Generating Random EC
        for x in range(10, 50):
            # Generate a Random EC Point with default NID ==> NID_secp256k1
            curveid: int = 714
            ec_pt = PyNakasendo.PyECPoint.PyECPoint((curveid))
            ec_pt.SetRandom()
            #hexValue = Nakasendo.ECPoint(curveid)

            # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
            assert ec_pt.CheckOnCurve(), "Test failed"
            x_axis, y_axis = ec_pt.GetAffineCoords()
            assert len(x_axis.ToHex()) == 62 or len(x_axis.ToHex()) == 64, "Test failed"
            # EC Point GetAffineCoOrdinates_GFp with default NID => NID_secp256k1
            bigNumpt = PyNakasendo.PyBigNumber.PyIntToBigNumber(x)
            listTupleObj.append((bigNumpt, ec_pt))

        #lgInterpolatorX = PyPolynomial.LGECInterpolatorFull(listTupleObj, modulo, xValue,dec, curveid)
        lgInterpolatorX = PyNakasendo.PyLGECInterpolator(listTupleObj, modulo)
        ec_pt = lgInterpolatorX(xValue, 714)
        assert ec_pt.CheckOnCurve(), "Test failed"
