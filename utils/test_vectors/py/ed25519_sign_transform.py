import sys
import binascii

# generates ed25519_sign.rs by using python3 ed25519_sign_transform.py < sign.input > ed25519_sign.rs
print("[")
while 1:
    line = sys.stdin.readline()
    if not line:
        break
    x = line.split(':')

    # 64-byte secret key - it consists of 32-byte seed and 32 additional bytes which
    # is effectively the SHA hash of the first 32 bytes.
    sk = binascii.unhexlify(x[0][0:64])
    pk = binascii.unhexlify(x[1])
    msg = binascii.unhexlify(x[2])
    # The first 64-byte are the signature followed by an exact copy of the message.
    sig = binascii.unhexlify(x[3][0:128])

    print("    TestVector {")
    print(f"        secret_key: \"{bytes(sk).hex()}\",")
    print(f"        public_key: \"{bytes(pk).hex()}\",")
    print(f"        message: \"{msg.hex()}\",")
    print(f"        signature: \"{sig.hex()}\",")
    print("    },")

print("]")
