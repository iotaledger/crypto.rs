---
"iota-crypto": minor
---

Add a `Aead` trait and expose a common API through the `Aes256Gcm` and `XChaCha20Poly1305` types.

To migrate from the previous `AES-GCM/ChaCha` implementations:

```rust
AES_256_GCM::encrypt(&key, &iv, &associated_data, &plaintext, &mut ciphertext, &mut tag)?;
// |
// v
Aes256Gcm::encrypt(&key, &iv, &associated_data, &plaintext, &mut ciphertext, &mut tag)?;
```

```rust
AES_256_GCM::decrypt(&key, &iv, &associated_data, &tag, &ciphertext, &mut plaintext)?;
// |
// v
Aes256Gcm::decrypt(&key, &nonce, &associated_data, &tag, &ciphertext, &mut plaintext)?;
```

```rust
xchacha20poly1305::encrypt(&mut ciphertext, &tag, &plaintext, &key, &nonce, &associated_data)?;
// |
// v
XChaCha20Poly1305::encrypt(&key, &nonce, &associated_data, &plaintext, &mut ciphertext, &mut tag)?;
```

```rust
xchacha20poly1305::decrypt(&mut plaintext, &ciphertext, &key, &tag, &nonce, &associated_data)?;
// |
// v
XChaCha20Poly1305::decrypt(&key, &nonce, &associated_data, &tag, &ciphertext, &mut plaintext)?;
```
