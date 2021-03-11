# Changelog

## [0.4.0]

-   Add a `Aead` trait and expose a common API through the `Aes256Gcm` and `XChaCha20Poly1305` types.

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

    - [104171d](https://www.github.com/iotaledger/crypto.rs/commit/104171d80555e3e62805ec59dd9e6290bcf71334) Add changelog message on 2021-03-04
    - [9690eae](https://www.github.com/iotaledger/crypto.rs/commit/9690eaedbb716649879a7f31dd60cc792ef5e2eb) Add migration note on 2021-03-04

-   Add AES Key Wrap algorithm.
    -   [523544f](https://www.github.com/iotaledger/crypto.rs/commit/523544f23ccb08cf75339996700b971bdc659d0e) Add changelog on 2021-01-09
-   Add ed25519 PublicKey Eq, Ord and AsRef traits.
    -   [4af8cab](https://www.github.com/iotaledger/crypto.rs/commit/4af8cab1358ae443d51b06ef32d31e5f0f6c2734) Implemented Eq, Ord and AsRef traits for ed25519 PublicKey on 2021-03-02
    -   [eec3caf](https://www.github.com/iotaledger/crypto.rs/commit/eec3cafdc1d9f132e041cdb91c08d6387d871ee7) Format and .changes typo fix. on 2021-03-02
-   Add ed25519 test suite.
    -   [56f1c11](https://www.github.com/iotaledger/crypto.rs/commit/56f1c11fb7be408e3a2426f9074fc46fc372b7e0) Added .changes file on 2021-02-18
-   Add HMAC-SHA384 message authentication algorithm.
    -   [a1d3926](https://www.github.com/iotaledger/crypto.rs/commit/a1d39267a3dbf2970efc7a481d880bcbf463006d) Add changelog message on 2020-12-18
-   Add PBKDF2-HMAC-SHA256/PBKDF2-HMAC-SHA384 key derivation.
    -   [8d6903b](https://www.github.com/iotaledger/crypto.rs/commit/8d6903bc0869a0261b075e9151226e75b0eaa756) Add changelog message on 2021-01-11
-   Add SHA384 hash function.
    -   [aa1734e](https://www.github.com/iotaledger/crypto.rs/commit/aa1734e9cc1297316a9a11e01bff60f2c1513ffc) Add changelog message on 2020-12-18
-   Add explicit Slip10 support for Ed25519 curve.
    -   [ac79610](https://www.github.com/iotaledger/crypto.rs/commit/ac7961011bb8f26d8c220e792217ceb44ed3cbba) Added slip10 supported curves on 2021-02-25
    -   [7f9544d](https://www.github.com/iotaledger/crypto.rs/commit/7f9544d6c83201aa2f17f53f536716acdddac8d5) Update .changes/add-slip10-curves.md on 2021-02-26
-   Add Slip10/Bip32 key derivation.
    -   [ef04de1](https://www.github.com/iotaledger/crypto.rs/commit/ef04de1793fe5b0464cacb51e5f2adb4a74e14c7) add .changes. on 2021-02-19
-   Add a `std` feature to implement `std::Error::Error` for `crypto::Error`.
    -   [370f07e](https://www.github.com/iotaledger/crypto.rs/commit/370f07e1012427695a8a1048ccc78f68742d2767) Add changelog message on 2021-03-09
-   Revision of verify scope to be `ed25519::PublicKey::verify`
    -   [f8c95fe](https://www.github.com/iotaledger/crypto.rs/commit/f8c95febd82f6cb71cd25e28c600dd27d795f254) chore(changefile) on 2021-03-03
-   Cleanup repo and revise layout of features into individual folders.
    -   [03acaa5](https://www.github.com/iotaledger/crypto.rs/commit/03acaa5550bd5b1dd270a098b28aca24fae13699) chore(changes): add changefile on 2021-03-03
-   Add the `Digest` trait and `Output` type to support streaming messages. Replace `blake2b::hash` with `hashes::blake2b::Blake2b256` (256-bit fixed-output).
    -   [b1ca2d8](https://www.github.com/iotaledger/crypto.rs/commit/b1ca2d890752c5f321e95d8964c9ca5c317f1a15) Add changelog message on 2021-02-17
    -   [f19de8d](https://www.github.com/iotaledger/crypto.rs/commit/f19de8d962634fff4ddf4083fe4c5b1cf7a5c6d0) chore(cleanup) on 2021-03-03
-   Add X25519 Diffie-Hellman key exchange and public key derivation using the Curve25519 curve.
    -   [a72b647](https://www.github.com/iotaledger/crypto.rs/commit/a72b64717447168edf384bb387850a4fd66a1e60) Add changelog message and document the Option&lt;\_> usage in the X25519 function on 2021-01-12
    -   [7c7d47e](https://www.github.com/iotaledger/crypto.rs/commit/7c7d47ebde64fc11296cd69f3f319a458b32cb03) Update .changes/x25519.md on 2021-02-05

## [0.2.0]

-   Add BIP39 wordlist codec.
    -   [ca2a5a5](https://www.github.com/iotaledger/crypto.rs/commit/ca2a5a59a830d00c4dbc3b186313bde9758247cc) add changlog on 2020-12-21
-   Introduce release manager for rust crates and npm packages including tangle registry.
    -   [d1b8ad3](https://www.github.com/iotaledger/crypto.rs/commit/d1b8ad31164d74cf22e443c65cffb24b12a403e2) feat/covector ([#20](https://www.github.com/iotaledger/crypto.rs/pull/20)) on 2020-11-26
-   Add HMAC-SHA256 and HMAC-SHA512 message authentication algorithms.
    -   [c6d8976](https://www.github.com/iotaledger/crypto.rs/commit/c6d89762c2635919c36b5ed41d17d6379ec7a0bc) Add changelog message on 2020-11-30
-   Add SHA256 and SHA512 hash functions.
    -   [5292638](https://www.github.com/iotaledger/crypto.rs/commit/529263843f7f0b78ef00d75922b1b1038b9b70ed) Add changelog message on 2020-11-30
