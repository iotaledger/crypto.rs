---
"iota-crypto": patch
---

Normalization of the parameters for the encryption and decryption functions.
- Parameter lists are as follows:
```rust
encrypt(
    key,
    nonce,
    associated_data,
    plaintext,
    ciphertext,
    tag
);

decrypt(
    key,
    nonce,
    associated_data,
    plaintext,
    ciphertext,
    tag
);

/// Returns the tag associated with the encryption.
try_encrypt(
    key,
    nonce,
    associated_data,
    plaintext,
    ciphertext
);

try_decrypt(
    key,
    nonce,
    associated_data,
    plaintext,
    ciphertext,
    tag
);
```

Changed the BufferSize error to include a name in the error message.

```rust
/// Produces an error message containing the following: 
/// $name buffer needs $needs bytes, but it only has $has

Error::BufferSize(
    name,
    needs,
    has
);
```