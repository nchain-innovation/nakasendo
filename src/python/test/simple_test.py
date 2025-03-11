from PyNakasendo import PyNakasendo
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def main() -> None:
    print('Starting BigNum')
    val = PyNakasendo.PyBigNumber()
    val.One()
    print(val)
    val.GenerateRandHex(512)
    print(val)

    val1 = PyNakasendo.PyBigNumber()
    val1.GenerateRandHex(512)
    val2 = PyNakasendo.PyBigNumber()
    val2.GenerateRandHex(512)

    val3 = val1 + val2

    print(f'val1 -> {val1}\nval2 -> {val2}')
    print(f'{type(val3)}')
    print(val3)
    val.One()
    val4 = val + 1
    print(val4)

def main_ec() -> None:
    print("starting ECPoint")
    #039381238A139463E2AC961E4B76E8F063E79353D4AADB3F0EA80A48A023998C00,-024C746B98B3834298104EB5582A966E8715673C5AB24CCA20457B12E95959ECF5,031409D41454F2024E32493EC3612E053A18282665B2F7D1FF459FF369C302A479
    ec_pt_a = PyNakasendo.PyECPoint(714)
    ec_pt_a.FromHex("039381238A139463E2AC961E4B76E8F063E79353D4AADB3F0EA80A48A023998C00")
    ec_pt_b = PyNakasendo.PyECPoint(714)
    ec_pt_b.FromHex("-024C746B98B3834298104EB5582A966E8715673C5AB24CCA20457B12E95959ECF5")
    ec_pt_res_file = PyNakasendo.PyECPoint(714)
    ec_pt_res_file.FromHex("031409D41454F2024E32493EC3612E053A18282665B2F7D1FF459FF369C302A479")

    print(f'pt_a -> {ec_pt_a.ToHex()} + pt_b -> {ec_pt_b.ToHex()}')


    ec_pt_no_param = PyNakasendo.PyECPoint()
    ec_pt_no_param.SetRandom()
    print(f'Random EC point defaulted to secp256k1-> {ec_pt_no_param}')
    
if __name__ == "__main__":
    main()
    main_ec()
    print('Testing BigNumber constructor')
    test_val = 123456789012345678901234567890
    val = PyNakasendo.PyIntToBigNumber(123456789012345678901234567890)
    print(val.ToDec())


    priv_key = PyNakasendo.PyAsymKey.PyAsymKey()
    print(f'Public key -> {priv_key}')
    msg_str = b"Alice want to say hello to Bob"
    # Create SHA-256 hash
    sha256_hash = hashlib.sha256(msg_str).digest()  # Raw bytes
    #print(sha256_hash)
    sha256_hex = hashlib.sha256(msg_str).hexdigest()  # Hex string
    print(sha256_hex)

    rSig, sSig = priv_key.sign_S256_bytes(sha256_hash)
    if PyNakasendo.PyAsymKey.verify_S256_bytes(sha256_hash, priv_key.exportPublicKeyPEM(), (rSig, sSig)):
        print("Valid signature")


    
    hello_world_hash = hashlib.sha256(b'hello world')
    hello_world_hex = hello_world_hash.hexdigest()
    print(hello_world_hex)

    input_str1 = "hello world"	
    expcted_str1 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    actual_Value1 = PyNakasendo.Utils.hash_sha256_str(input_str1)
    print(type(actual_Value1))
    print(actual_Value1.hex())
    assert actual_Value1.hex() == expcted_str1 == hello_world_hex
    print('Ending')


    empty_hash = hashlib.sha256(b'')
    empty_hex = empty_hash.hexdigest()
    print(empty_hex)

    bitcoin_hash = hashlib.sha256(b'Bitcoin')
    bitcoin_hex = bitcoin_hash.hexdigest()
    print(bitcoin_hex)

    hello_world_hash = hashlib.sha512(b'hello world')
    hello_world_hex = hello_world_hash.hexdigest()
    print(hello_world_hex)

    empty_hash = hashlib.sha512(b'')
    empty_hex = empty_hash.hexdigest()
    print(empty_hex)

    bitcoin_hash = hashlib.sha512(b'Bitcoin')
    bitcoin_hex = bitcoin_hash.hexdigest()
    print(bitcoin_hex)

    hello_world_double_hash = hashlib.sha256(hashlib.sha256(b'hello world').digest())
    hello_world_double_hex = hello_world_double_hash.hexdigest()
    print(hello_world_double_hex)
    assert hello_world_double_hex != hello_world_hex

    empty_hash = hashlib.sha256(hashlib.sha256(b'').digest())
    empty_hex = empty_hash.hexdigest()
    print(empty_hex)

    bitcoin_hash = hashlib.sha256(hashlib.sha256(b'Bitcoin').digest())
    bitcoin_hex = bitcoin_hash.hexdigest()
    print(bitcoin_hex)

    password_test = "password123"
    nonce = "random_salt"
    # Set up PBKDF2
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=nonce.encode(),
    iterations=10000,
    )

    # Generate a key
    # key = kdf.derive(b"password123")
    key = kdf.derive(password_test.encode())

    key1: str = PyNakasendo.Utils.GenerateKey(password_test, nonce)

    # Encode the key in base64 or hex for readability
    print("Derived Key (Hex):", key.hex())
    print(f'derived other key (hex): {key1}')
    #print("Derived Key (Base64):", base64.b64encode(key).decode())


