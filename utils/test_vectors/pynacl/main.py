import random
import secrets
from base64 import b64encode

from nacl.signing import SigningKey

def fresh_bytes(n):
    return secrets.token_bytes(n)

def print_ed25519_test_vector():
    sk = SigningKey.generate()
    pk = sk.verify_key
    msg = fresh_bytes(random.randint(0, 256))
    sig = sk.sign(msg).signature

    print("TestVector {")
    print(f"    secret_key: \"{bytes(sk).hex()}\",")
    print(f"    public_key: \"{bytes(pk).hex()}\",")
    print(f"    message: \"{msg.hex()}\",")
    print(f"    signature: \"{sig.hex()}\",")
    print("},")

if __name__ == "__main__":
    print_ed25519_test_vector()
