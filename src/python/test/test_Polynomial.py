
import unittest
from PyNakasendo import PyNakasendo
from random import randint

def polynomialEvaluation(coefficients, xValue, mod, decHex):

    # evaluate polynomial for x
    polynomialFX = PyPolynomial.evaluate(coefficients, xValue, mod, decHex)
    assert type(polynomialFX) == str, "Test failed"
    return polynomialFX

def polynomial_evaluate(a_list, fx, mod):

    ans = 0
    for n, a in enumerate(a_list):
        ans += a * fx ** n

    ans %= mod
    return ans


class PolynomialTests(unittest.TestCase):
    def test_InitFromListCoefficient(self):

        # the polynomial of f = 3x^4 + 13x^3 + 5x^2 + 2x + 1
        # and working with the modulo equal 17 and the degree equal 4
        # evaluate the polynomial at x equal 2.
        # the expression will f(2) = ((3 x 2^4) + (13 x 2^3) + (5 x 2^2) + (2 x 2) + 1) mod 17 = 7

        coefficients = ["1", "2", "5", "13", "3"]
        degree = 4
        mod = "17"
        x = "2"
        dec = 1

        # create a Polynomial from a list of coefficients
        listCoefficients = PyPolynomial.initFromList(coefficients, dec)
        assert len(listCoefficients) == degree + 1, "Test failed"

        # Calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, x, mod, dec)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(coefficients)):
            lst.append(int(coefficients[i]))

        actualValue = polynomial_evaluate(lst, int(x), int(mod))
        assert polynomialFX == str(actualValue), "Test failed"
'''
def test_InitFromListCoefficientWithZeroDegree():

    # The random polynomial generator refuses to generate a polynomial of degree 0. However,
    # pushing coefficients via the coefficient constructor can construct a degree 0 polynomial,
    # which the API should generate error.
    coefficients = ["18"]
    degree = 0
    mod = "17"
    x = "2"
    dec = 1

    # create a Polynomial from a list of coefficients
    listCoefficients = PyPolynomial.initFromList(coefficients, dec)
    assert len(listCoefficients) == degree + 1, "Test failed"

    # Calling evaluate polynomial function
    polynomialFX = polynomialEvaluation(listCoefficients, x, mod, dec)

    # convert list of coefficients from string to decimal
    lst = []
    for i in range(len(coefficients)):
        lst.append(int(coefficients[i]))

    actualValue = polynomial_evaluate(lst, int(x), int(mod))
    assert polynomialFX == str(actualValue), "Test failed"

def test_InitFromListDec():

    for x in range(10, 15):

        fx = str(randint(10, 100000))
        modulo = str(PyBigNumbers.GenerateRandPrimeDec(100))
        listCoefficients = []
        dec = 1

        for i in range(x):
            # Generate random coefficients for the polynomial
            listCoefficients.append(str(randint(100000, 1000000)))

        # create a Polynomial from a list of coefficients
        allCoeffeicient = PyPolynomial.initFromList(listCoefficients, dec)
        assert len(allCoeffeicient) == x, "Test failed"

        # Calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, dec)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(allCoeffeicient)):
            lst.append(int(allCoeffeicient[i]))

        fx = int(fx)
        modulo = int(modulo)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX == str(actualValue), "Test failed"

def test_InitFromListHex():

    hex_value = 0
    for x in range(10, 15):

        fx = PyBigNumbers.GenerateRandHex(256)
        modulo = PyBigNumbers.GenerateRandPrimeHex(100)
        listCoefficients = []

        for i in range(x):
            # Generate random coefficients for the polynomial
            listCoefficients.append(PyBigNumbers.GenerateRandHex(256))

        # create a Polynomial from a list of coefficients
        allCoeffeicient = PyPolynomial.initFromList(listCoefficients, hex_value)
        assert len(allCoeffeicient) == x, "Test failed"

        # Calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, hex_value)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(allCoeffeicient)):
            lst.append(int(allCoeffeicient[i], 16))

        fx = int(fx, 16)
        modulo = int(modulo, 16)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX.lstrip("0") == hex(actualValue).upper().lstrip("0X"), "Test failed"

def test_InitFromListModuloDec():

    for x in range(10, 15):

        modHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        fx = str(randint(10, 100000))
        modulo = str(int(modHex, 16))
        # modulo = str(PyBigNumbers.GenerateRandPrimeDec(100))
        degree = randint(10, 15)
        dec = 1

        # create a random polynomial
        listCoefficients = PyPolynomial.randomPolynomial(degree, modulo, dec)
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # create a Polynomial from a list of coefficient with modulo
        coefficientsWithModulo = PyPolynomial.initFromListModulo(listCoefficients, modulo, dec)
        assert len(coefficientsWithModulo) == degree + 1, "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(coefficientsWithModulo, fx, modulo, dec)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(coefficientsWithModulo)):
            lst.append(int(coefficientsWithModulo[i]))

        fx = int(fx)
        modulo = int(modulo)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX == str(actualValue), "Test failed"

def test_InitFromListModuloHex():

    for x in range(10, 15):

        modHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        fx = PyBigNumbers.GenerateRandHex(256)
        degree = randint(10, 15)
        hex_value = 0

        # create a random polynomial
        listCoefficients = PyPolynomial.randomPolynomial(degree, modHex, hex_value)
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # create a Polynomial from a list of coefficient with modulo
        coefficientsWithModulo = PyPolynomial.initFromListModulo(listCoefficients, modHex, hex_value)
        assert len(coefficientsWithModulo) == degree + 1, "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(coefficientsWithModulo, fx, modHex, hex_value)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(coefficientsWithModulo)):
            lst.append(int(coefficientsWithModulo[i], 16))

        fx = int(fx, 16)
        modulo = int(modHex, 16)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX.lstrip("0") == hex(actualValue).upper().lstrip("0X"), "Test failed"

def test_RandomPolynomialDec():

    for x in range(5):

        fx = PyBigNumbers.GenerateRandDec(256)
        degree = randint(10, 15)
        modulo = PyBigNumbers.GenerateRandPrimeDec(100)
        dec = 1

        # create a random polynomial
        listCoefficients = PyPolynomial.randomPolynomial(degree, modulo, dec)
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, dec)
        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(listCoefficients)):

            lst.append(int(listCoefficients[i]))

        fx = int(fx)
        modulo = int(modulo)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX == str(actualValue), "Test failed"

def test_RandomPolynomialHex():

    for x in range(5):

        fx = PyBigNumbers.GenerateRandHex(256)
        degree = randint(10, 15)
        modulo = PyBigNumbers.GenerateRandPrimeHex(100)
        hex_value = 0

        # create a random polynomial
        listCoefficients = PyPolynomial.randomPolynomial(degree, modulo, hex_value)
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, hex_value)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(listCoefficients)):
            lst.append(int(listCoefficients[i], 16))

        fx = int(fx, 16)
        modulo = int(modulo, 16)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX.lstrip("0") == hex(actualValue).upper().lstrip("0X"), "Test failed"

def test_RandomPolynomialFixed_a_0_Dec():

    for x in range(5):

        fx = str(randint(10, 100000))
        degree = randint(10, 15)
        modulo = str(randint(2001, 100000))
        a_0 = str(randint(1000, 2000))
        dec = 1

        # create a random polynomial with fixed a_0
        listCoefficients = PyPolynomial.randomPolynomialFixed_a_0(degree, modulo, a_0, dec)
        assert listCoefficients[0] == a_0, "Test failed"
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, dec)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(listCoefficients)):
            lst.append(int(listCoefficients[i]))

        fx = int(fx)
        modulo = int(modulo)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX == str(actualValue), "Test failed"

def test_RandomPolynomialMinMaxDec():

    for x in range(10, 15):

        fx = str(randint(10, 100000))
        degree = randint(10, 15)
        dec = 1
        modulo = str(randint(1000, 100000))
        min = str(randint(100, 100000))
        max = str(randint(100001, 200000))

        # create a random polynomial with range of min..max
        listCoefficients = PyPolynomial.randomPolynomialMinMax(degree, modulo, min, max, dec)
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, dec)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(listCoefficients)):
            lst.append(int(listCoefficients[i]))

        fx = int(fx)
        modulo = int(modulo)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX == str(actualValue), "Test failed"

def test_RandomPolynomialMinMaxHex():

    for x in range(5):

        fx = PyBigNumbers.GenerateRandHex(256)
        degree = randint(10, 15)
        hex_value = 0
        modulo = str(randint(100000, 10000000))
        min = str(randint(10000, 10000000))
        max = str(randint(10000001, 100000000))

        # create a random polynomial with range of min..max
        listCoefficients = PyPolynomial.randomPolynomialMinMax(degree, modulo, min, max, hex_value)
        assert len(listCoefficients) == (degree + 1), "Test failed"

        # calling evaluate polynomial function
        polynomialFX = polynomialEvaluation(listCoefficients, fx, modulo, hex_value)

        # convert list of coefficients from string to decimal
        lst = []
        for i in range(len(listCoefficients)):
            lst.append(int(listCoefficients[i], 16))

        fx = int(fx, 16)
        modulo = int(modulo, 16)
        actualValue = polynomial_evaluate(lst, fx, modulo)
        assert polynomialFX.lstrip("0") == hex(actualValue).upper().lstrip("0X"), "Test failed"

def test_LGInterpolatorFullDec():

    listTupleObj = [(2, "10"), (3, "15")]
    modulo = "0"
    dec = 1

    for x in range(100, 110):
        randomX = randint(1000, 1000000)
        xValue = str(randomX)

        # LGInterpolator, full evaluation of the polynomial at xValue
        lgInterpolatorX = PyPolynomial.LGInterpolatorFull(listTupleObj, modulo, xValue, dec)
        assert lgInterpolatorX == str(randomX * 5), "Test failed"

def test_LGInterpolatorFullHex():

    listTupleObj = [(2, "A"), (3, "F")]
    modulo = "0"
    hex_value = 0

    for x in range(100, 110):
        randomX = PyBigNumbers.GenerateRandHex(100000)
        xValue = str(randomX)
        # LGInterpolator, full evaluation of the polynomial at xValue
        lgInterpolatorX = PyPolynomial.LGInterpolatorFull(listTupleObj, modulo, xValue, hex_value)
        assert lgInterpolatorX.lstrip("0") == hex(int(randomX, 16) * 5).lstrip("0x").upper(), "Test failed"

def test_LGInterpolatorSingleHex():

    listTupleObj = [(1, "13"), (2, "4"), (3, "2"), (4, "5"), (5, "11"), (6, "1")]
    modulo = PyBigNumbers.GenerateRandPrimeHex(100)
    hex_value = 0
    xValue = str(randint(10, 100000))

    for x in range(1, 6):
        xPoint = str(x)
        # LGInterpolator, evaluate the ith basis polynomial at xValue
        lgInterpolatorX = PyPolynomial.LGInterpolatorSingle(listTupleObj, modulo, xValue, xPoint, hex_value)
        assert type(lgInterpolatorX) == str, "Test failed"

def test_LGInterpolatorSingleDec():

    listTupleObj = [(1, "13"), (2, "4"), (3, "2"), (4, "5"), (5, "11"), (6, "1")]
    modulo = str(PyBigNumbers.GenerateRandPrimeDec(100))
    dec = 1
    xValue = str(randint(10, 100000))

    for x in range(1, 6):
        xPoint = str(x)

        # LGInterpolator, evaluate the ith basis polynomial at xValue
        lgInterpolatorX = PyPolynomial.LGInterpolatorSingle(listTupleObj, modulo, xValue, xPoint, dec)
        assert type(lgInterpolatorX) == str, "Test failed"

def test_LGECInterpolatorFull():

    modulo = PyBigNumbers.GenerateRandPrimeHex(1000)
    xValue = PyBigNumbers.GenerateRandHex(1000)
    listTupleObj = []
    dec = False

    # Generating Random EC
    for x in range(10, 50):
        # Generate a Random EC Point with default NID ==> NID_secp256k1
        curveid: int = 714
        hexValue = Nakasendo.ECPoint(curveid)

        # Check if the point is on the curve with the supplied NID default NID ==> NID_secp256k1
        assert hexValue.IsPointOnCurve(), "Test failed"

        x_Axis, y_axis = hexValue.GetAffineCoOrdinates()
        # EC Point GetAffineCoOrdinates_GFp with default NID => NID_secp256k1
        listTupleObj.append((str(x), x_Axis, y_axis))

    lgInterpolatorX = PyPolynomial.LGECInterpolatorFull(listTupleObj, modulo, xValue,dec, curveid)
    assert type(lgInterpolatorX) == str, "Test failed"
'''