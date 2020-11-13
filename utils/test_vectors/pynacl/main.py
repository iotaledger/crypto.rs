import random
import secrets
from base64 import b64encode

from nacl.signing import SigningKey
from Crypto.Cipher import ChaCha20_Poly1305

def fresh_bytes(n=None, bound=None):
    if n is None:
        if bound is None:
            bound = 256
        n = random.randint(0, bound)
    return secrets.token_bytes(n)

def coinflip():
    return random.choice([True, False])

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

def print_xchacha20poly1305_test_vector():
    pt = fresh_bytes()
    k = fresh_bytes(32)
    n = fresh_bytes(24)
    c = ChaCha20_Poly1305.new(key=k, nonce=n)
    if coinflip():
        ad = fresh_bytes()
        c.update(ad)
    else:
        ad = bytes()
    (ct, t) = c.encrypt_and_digest(pt)
    print("TestVector {")
    print(f"    plaintext: \"{pt.hex()}\",")
    print(f"    associated_data: \"{ad.hex()}\",")
    print(f"    key: \"{k.hex()}\",")
    print(f"    nonce: \"{n.hex()}\",")
    print(f"    ciphertext: \"{ct.hex()}\",")
    print(f"    tag: \"{t.hex()}\",")
    print("},")

if __name__ == "__main__":
    print_xchacha20poly1305_test_vector()
