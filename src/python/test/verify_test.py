import ecdsa
from hashlib import sha256

def run_verify_with_sha():
    print("verify test")
    pub_key_pem = '''-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEkguwCncj93DjtY+UgDngaV2xOejVvXYG
1jOimCcJ6OJ5T5na2OJfPP+7O+ySlhJYs6IjgVPctwe1Pr/8ClPRfA==
-----END PUBLIC KEY-----'''

    sig_str = "3045022049B7B06EC6F25D801AAD70B723C4DD96821EB078FD3DFB7CD6A59C7E57E0DD22022100B4F3A4A69BB280CCF48DBDCBDE2744F257C5EE12817CB9064128402BF5963DF9"
    sig_str_bytes = bytes.fromhex(sig_str)
    msg_str_bytes = b"Alice want to say hello to Bob"
    #sha256_msg_bytes = bytes.fromhex(msg_str)
    vk = ecdsa.VerifyingKey.from_pem(pub_key_pem)
    try:
        ret = vk.verify(sig_str_bytes, msg_str_bytes, sha256, sigdecode=ecdsa.util.sigdecode_der)
        assert(ret)
        print("Valid signature")
    except ecdsa.BadSignatureError:
        print("Incorrect signature")

def run_verify_no_sha_str():
    print("verify test str, no sha")
    sig_str = "304402207C18D50749EEA8C8A2CE19730C61F5EAF8C22DD1FE79F0E04ED52A299C41D05D02202A35685A04610FFAA062D8CFC666D1FD87DC56E5D8CA634E8915363B2BDB12DC"
    sig_str_bytes = bytes.fromhex(sig_str)
    #msg_str = "Alice want to say hello to Bob"
    #msg_str_raw_bytes = b"Alice want to say hello to Bob"
    # Convert string to bytes (UTF-8 encoding)
    # input_bytes = msg_str.encode('utf-8')

    # Create SHA-256 hash
    #sha256_hash = sha256(msg_str_raw_bytes).digest()  # Raw bytes
    #print(sha256_hash)
    #sha256_hex = sha256(msg_str_raw_bytes).hexdigest()  # Hex string
    #print(sha256_hex)
    msg_str_bytes = bytes.fromhex("e340b16b195b671a850df55e3242534f0c8094140fd0681ed14e144f29248497")
    #assert(sha256_hash == msg_str_bytes)
    pub_key_pem = '''-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEL4lJeewZIkDhfDWrrP8H0JmF28P/2DHf
JHTcu/vR5rMxijXE0Qnr8mD76IiQpt/eUS5lnMO2desh+Ds1oU3yww==
-----END PUBLIC KEY-----'''
    vk = ecdsa.VerifyingKey.from_pem(pub_key_pem)
    try:
        ret = vk.verify_digest(sig_str_bytes, msg_str_bytes, sigdecode=ecdsa.util.sigdecode_der)
        assert(ret)
        print("Valid signature - test_no_sha")
    except ecdsa.BadSignatureError:
        print("Incorrect signature")

def  run_verify_no_sha_bytes():
    
    pass

if __name__ == "__main__":
    run_verify_with_sha()
    run_verify_no_sha_str()

    run_verify_no_sha_bytes()

'''
from hashlib import sha256
from ecdsa import BadSignatureError
from ecdsa.util import sigdecode_der

with open("message.sig", "rb") as f:
    sig = f.read()

try:
    ret = public_key.verify(sig, message, sha256, sigdecode=sigdecode_der)
    assert ret
    print("Valid signature")
except BadSignatureError:
    print("Incorrect signature")
'''