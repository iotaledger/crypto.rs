# Changelog

## \[0.11.0]

- Add AES-CBC algorithms (`Aes128CbcHmac256`, `Aes192CbcHmac384`, `Aes256CbcHmac512`).
  - [8454c9b](https://www.github.com/iotaledger/crypto.rs/commit/8454c9b8279bd40ef4e5b20b8dad496b21a269fc) Add AES-CBC ([#41](https://www.github.com/iotaledger/crypto.rs/pull/41)) on 2022-05-12

## \[0.10.0]

- Bump version minor to fix https://github.com/iotaledger/bee/issues/1360
  - [95662a7](https://www.github.com/iotaledger/crypto.rs/commit/95662a79448907cc9bf572595fc178b4fbc61531) Bump version minor ([#134](https://www.github.com/iotaledger/crypto.rs/pull/134)) on 2022-05-04

## \[0.9.2]

- Bump version of `bee-ternary` to `v0.6.0`
  - [bbb25e4](https://www.github.com/iotaledger/crypto.rs/commit/bbb25e45fd8482ef30d1d913622a875251c95f48) Add change file ([#131](https://www.github.com/iotaledger/crypto.rs/pull/131)) on 2022-04-25

## \[0.9.1]

- Make `iota-crypto` `no_std`.
  - [6b7b524](https://www.github.com/iotaledger/crypto.rs/commit/6b7b524bf90a08af40752b5cecf3d04ac0f30098) Make curl_p module no_std ([#118](https://www.github.com/iotaledger/crypto.rs/pull/118)) on 2021-11-19

## \[0.9.0]

- Replace Curl implementation with an unrolled version for better performance.
  Add a batched version of Curl.
  - [18ab209](https://www.github.com/iotaledger/crypto.rs/commit/18ab209cd6c842b310ff614af840ebf3f1c70022) Add unrolled curl and batched curl ([#116](https://www.github.com/iotaledger/crypto.rs/pull/116)) on 2021-11-19

## \[0.8.0]

- Support for the Blake2b hashing function to 160 bits

- Wrapper around VarBlake2b for 160 bits hash

- New tests for 160 bits copied from blake2b-256

- Generate new test vector created with b2sum using the inputs of blake2b-256 test vector

- Update list of supported algorithms

- [dd055a4](https://www.github.com/iotaledger/crypto.rs/commit/dd055a4a1df8866228334086c8f13d1a05096bce) Add Blake2b-160 ([#111](https://www.github.com/iotaledger/crypto.rs/pull/111)) on 2021-10-27

- Update bee-ternary requirement from 0.4.2-alpha to 0.5.0
  - [5f3c9d2](https://www.github.com/iotaledger/crypto.rs/commit/5f3c9d2770760eaaf32880322f45d57518d24fd0) Add .changes file for bee-ternary bump ([#115](https://www.github.com/iotaledger/crypto.rs/pull/115)) on 2021-11-11

## \[0.7.0]

- - Enabled to access the `Segment` vector in `Chain`.
- Added consistent line breaks between methods.
- [50c0f53](https://www.github.com/iotaledger/crypto.rs/commit/50c0f53262861cdb4f3728a9a8c4e67b53ec68f0) Add .change file for Chain access on 2021-07-02
- - Unified naming convention in ed25519 and x25519 modules.
- Added useful methods and standard traits implementations.
- Added conversion of ed25519 keys to x25519 keys.
- [b52caec](https://www.github.com/iotaledger/crypto.rs/commit/b52caec7a8890049407ce4ce02488a31578d155a) added changes on 2021-07-28

## \[0.6.0]

- Added js feature to getrandom for wasm compatibility.
  - [0a85dfd](https://www.github.com/iotaledger/crypto.rs/commit/0a85dfd161b46ba9a932ff84aa3e3ad9e27d2d08) add change file on 2021-07-01

- Added

- `Segment` field access;
  - Enable `hardened` field read access;
  - Enable `bs` field read access;

- `bip39.rs` clippy error fix;

- [41e776e](https://www.github.com/iotaledger/crypto.rs/commit/41e776ec77ff6291cf804b5e13687b373df89b51) Add .changes file for Segment field access on 2021-07-01

## \[0.5.1]

- This release updates a number of interlocking dependencies, but does not change the external interface.
  - [a644f8d](https://www.github.com/iotaledger/crypto.rs/commit/a644f8d8e62b40071634d4c15efebc5942c2bd90) add .changefile on 2021-05-04

## \[0.5.0]

- Added

- `Sponge` trait;

- `Kerl` sponge implementation;

- [f96b845](https://www.github.com/iotaledger/crypto.rs/commit/f96b845948a8f3ab02ff30126837499b7e015c1d) Add .change on 2021-04-16

- [12df494](https://www.github.com/iotaledger/crypto.rs/commit/12df494bf837981db3cf026a2f57148c8756a0cf) Update .changes/kerl.md on 2021-04-16

- Added

- `WOTS` implementation;
  - `keys` module;
  - `signatures` module;

- [eec08c3](https://www.github.com/iotaledger/crypto.rs/commit/eec08c3af29a92a6dfbeb56b23a272a38b0de606) Add wots .changes on 2021-04-18

## \[0.4.2]

- Automated publishing
  - [30342ce](https://www.github.com/iotaledger/crypto.rs/commit/30342ce0586b66b85f565e9e0489c1fd32ac035d) .changes on 2021-03-18

## \[0.4.1]

- Patch to fix publish workflow.
  - [f161741](https://www.github.com/iotaledger/crypto.rs/commit/f161741b56b491331d202385268500c6328da7af) fix(covector) on 2021-03-18

## \[0.4.0]

- Add a `Aead` trait and expose a common API through the `Aes256Gcm` and `XChaCha20Poly1305` types.

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

- Add AES Key Wrap algorithm.
  - [523544f](https://www.github.com/iotaledger/crypto.rs/commit/523544f23ccb08cf75339996700b971bdc659d0e) Add changelog on 2021-01-09

- Add ed25519 PublicKey Eq, Ord and AsRef traits.
  - [4af8cab](https://www.github.com/iotaledger/crypto.rs/commit/4af8cab1358ae443d51b06ef32d31e5f0f6c2734) Implemented Eq, Ord and AsRef traits for ed25519 PublicKey on 2021-03-02
  - [eec3caf](https://www.github.com/iotaledger/crypto.rs/commit/eec3cafdc1d9f132e041cdb91c08d6387d871ee7) Format and .changes typo fix. on 2021-03-02

- Add ed25519 test suite.
  - [56f1c11](https://www.github.com/iotaledger/crypto.rs/commit/56f1c11fb7be408e3a2426f9074fc46fc372b7e0) Added .changes file on 2021-02-18

- Add HMAC-SHA384 message authentication algorithm.
  - [a1d3926](https://www.github.com/iotaledger/crypto.rs/commit/a1d39267a3dbf2970efc7a481d880bcbf463006d) Add changelog message on 2020-12-18

- Add PBKDF2-HMAC-SHA256/PBKDF2-HMAC-SHA384 key derivation.
  - [8d6903b](https://www.github.com/iotaledger/crypto.rs/commit/8d6903bc0869a0261b075e9151226e75b0eaa756) Add changelog message on 2021-01-11

- Add SHA384 hash function.
  - [aa1734e](https://www.github.com/iotaledger/crypto.rs/commit/aa1734e9cc1297316a9a11e01bff60f2c1513ffc) Add changelog message on 2020-12-18

- Add explicit Slip10 support for Ed25519 curve.
  - [ac79610](https://www.github.com/iotaledger/crypto.rs/commit/ac7961011bb8f26d8c220e792217ceb44ed3cbba) Added slip10 supported curves on 2021-02-25
  - [7f9544d](https://www.github.com/iotaledger/crypto.rs/commit/7f9544d6c83201aa2f17f53f536716acdddac8d5) Update .changes/add-slip10-curves.md on 2021-02-26

- Add Slip10/Bip32 key derivation.
  - [ef04de1](https://www.github.com/iotaledger/crypto.rs/commit/ef04de1793fe5b0464cacb51e5f2adb4a74e14c7) add .changes. on 2021-02-19

- Add a `std` feature to implement `std::Error::Error` for `crypto::Error`.
  - [370f07e](https://www.github.com/iotaledger/crypto.rs/commit/370f07e1012427695a8a1048ccc78f68742d2767) Add changelog message on 2021-03-09

- Revision of verify scope to be `ed25519::PublicKey::verify`
  - [f8c95fe](https://www.github.com/iotaledger/crypto.rs/commit/f8c95febd82f6cb71cd25e28c600dd27d795f254) chore(changefile) on 2021-03-03

- Cleanup repo and revise layout of features into individual folders.
  - [03acaa5](https://www.github.com/iotaledger/crypto.rs/commit/03acaa5550bd5b1dd270a098b28aca24fae13699) chore(changes): add changefile on 2021-03-03

- Normalization of the parameters for the encryption and decryption functions.

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

try_encrypt(
    key,
    nonce,
    associated_data,
    plaintext,
    ciphertext,
    tag
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

    - [ef8e5b9](https://www.github.com/iotaledger/crypto.rs/commit/ef8e5b9ad65f315cea3473979b80590bb439aaea) add .changes md. on 2021-03-13
    - [bca7a4d](https://www.github.com/iotaledger/crypto.rs/commit/bca7a4da2ffbf7e9422b74285fb605b748f06274) update .changes. on 2021-03-15

- Add the `Digest` trait and `Output` type to support streaming messages. Replace `blake2b::hash` with `hashes::blake2b::Blake2b256` (256-bit fixed-output).
  - [b1ca2d8](https://www.github.com/iotaledger/crypto.rs/commit/b1ca2d890752c5f321e95d8964c9ca5c317f1a15) Add changelog message on 2021-02-17
  - [f19de8d](https://www.github.com/iotaledger/crypto.rs/commit/f19de8d962634fff4ddf4083fe4c5b1cf7a5c6d0) chore(cleanup) on 2021-03-03
- Add X25519 Diffie-Hellman key exchange and public key derivation using the Curve25519 curve.
  - [a72b647](https://www.github.com/iotaledger/crypto.rs/commit/a72b64717447168edf384bb387850a4fd66a1e60) Add changelog message and document the Option<\_> usage in the X25519 function on 2021-01-12
  - [7c7d47e](https://www.github.com/iotaledger/crypto.rs/commit/7c7d47ebde64fc11296cd69f3f319a458b32cb03) Update .changes/x25519.md on 2021-02-05

## \[0.2.0]

- Add BIP39 wordlist codec.
  - [ca2a5a5](https://www.github.com/iotaledger/crypto.rs/commit/ca2a5a59a830d00c4dbc3b186313bde9758247cc) add changlog on 2020-12-21
- Introduce release manager for rust crates and npm packages including tangle registry.
  - [d1b8ad3](https://www.github.com/iotaledger/crypto.rs/commit/d1b8ad31164d74cf22e443c65cffb24b12a403e2) feat/covector ([#20](https://www.github.com/iotaledger/crypto.rs/pull/20)) on 2020-11-26
- Add HMAC-SHA256 and HMAC-SHA512 message authentication algorithms.
  - [c6d8976](https://www.github.com/iotaledger/crypto.rs/commit/c6d89762c2635919c36b5ed41d17d6379ec7a0bc) Add changelog message on 2020-11-30
- Add SHA256 and SHA512 hash functions.
  - [5292638](https://www.github.com/iotaledger/crypto.rs/commit/529263843f7f0b78ef00d75922b1b1038b9b70ed) Add changelog message on 2020-11-30
