# Copyright 2020 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import random
import secrets
from base64 import b64encode
import hashlib
import hmac

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

def print_sha256_test_vector(n=None):
    msg = fresh_bytes(n=n, bound=1024)
    digest = hashlib.sha256(msg).digest()
    print("TestVector {")
    print(f"    msg: \"{msg.hex()}\",")
    print(f"    digest: \"{digest.hex()}\",")
    print("},")

def print_sha384_test_vector(n=None):
    msg = fresh_bytes(n=n, bound=1024)
    digest = hashlib.sha384(msg).digest()
    print("TestVector {")
    print(f"    msg: \"{msg.hex()}\",")
    print(f"    digest: \"{digest.hex()}\",")
    print("},")

def print_sha512_test_vector(n=None):
    msg = fresh_bytes(n=n, bound=1024)
    digest = hashlib.sha512(msg).digest()
    print("TestVector {")
    print(f"    msg: \"{msg.hex()}\",")
    print(f"    digest: \"{digest.hex()}\",")
    print("},")

def print_hmac_sha256_test_vector():
    data = fresh_bytes(bound=1024)
    key = fresh_bytes(bound=1024)
    mac = hmac.new(key=key, msg=data, digestmod="sha256").digest()
    print("TestVector {")
    print(f"    data: \"{data.hex()}\",")
    print(f"    key: \"{key.hex()}\",")
    print(f"    mac: \"{mac.hex()}\",")
    print("},")

def print_hmac_sha384_test_vector():
    data = fresh_bytes(bound=1024)
    key = fresh_bytes(bound=1024)
    mac = hmac.new(key=key, msg=data, digestmod="sha384").digest()
    print("TestVector {")
    print(f"    data: \"{data.hex()}\",")
    print(f"    key: \"{key.hex()}\",")
    print(f"    mac: \"{mac.hex()}\",")
    print("},")

def print_hmac_sha512_test_vector():
    data = fresh_bytes(bound=1024)
    key = fresh_bytes(bound=1024)
    mac = hmac.new(key=key, msg=data, digestmod="sha512").digest()
    print("TestVector {")
    print(f"    data: \"{data.hex()}\",")
    print(f"    key: \"{key.hex()}\",")
    print(f"    mac: \"{mac.hex()}\",")
    print("},")


def print_pbkdf2_hmac_sha256_test_vector():
    password = fresh_bytes(bound=1024)
    salt = fresh_bytes(bound=1024)
    c = random.randint(1, 100000)
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, c)
    print("TestVector {")
    print(f"    password: \"{password.hex()}\",")
    print(f"    salt: \"{salt.hex()}\",")
    print(f"    c: {c},")
    print(f"    dk: \"{dk.hex()}\",")
    print("},")

def print_pbkdf2_hmac_sha384_test_vector():
    password = fresh_bytes(bound=1024)
    salt = fresh_bytes(bound=1024)
    c = random.randint(1, 100000)
    dk = hashlib.pbkdf2_hmac('sha384', password, salt, c)
    print("TestVector {")
    print(f"    password: \"{password.hex()}\",")
    print(f"    salt: \"{salt.hex()}\",")
    print(f"    c: {c},")
    print(f"    dk: \"{dk.hex()}\",")
    print("},")

def print_pbkdf2_hmac_sha512_test_vector():
    password = fresh_bytes(bound=1024)
    salt = fresh_bytes(bound=1024)
    c = random.randint(1, 100000)
    dk = hashlib.pbkdf2_hmac('sha512', password, salt, c)
    print("TestVector {")
    print(f"    password: \"{password.hex()}\",")
    print(f"    salt: \"{salt.hex()}\",")
    print(f"    c: {c},")
    print(f"    dk: \"{dk.hex()}\",")
    print("},")

if __name__ == "__main__":
    print_pbkdf2_hmac_sha512_test_vector()
