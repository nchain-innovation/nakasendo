import sys
import hashlib
import ecdsa 

if __name__ == "__main__":
    print ("...starting....")
    #print (sys.argv)
    sigRStr = sys.argv[1]
    sigSStr = sys.argv[2]
    pubKeyStr = sys.argv[3]
    message = sys.argv[4]

    hashed_msg = hashlib.sha256(message.encode()).digest()

    # Convert r and s to integers
    r = int(sigRStr, 16)
    s = int(sigSStr, 16)

    # Load the public key from hex
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubKeyStr), curve=ecdsa.SECP256k1)

    # Create a signature object from r and s
    signature = ecdsa.util.sigencode_der(r, s, vk.curve.order)
    print(signature)
    print(f'signature type -> {type(signature)}')
    # Verify the signature
    is_valid = vk.verify(signature, message.encode(), hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)

    print("Signature is valid:", is_valid)


