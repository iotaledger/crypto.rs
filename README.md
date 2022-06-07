# crypto.rs

### A fork of the Iotaledger crypto.rs library. 

A boundary crate of selected implementations of crypto primitives that are considered to be safe to use within the IOTA Foundation.

To be included in this list an implementation must:
* expose a minimal interface using the simplest possible types with high semantic density
* be explicit what algorithm they perform (e.g. `PBKDF_HMAC_SHA512`)
* use explicit memory allocation whenever possible and prefer `no_std`
* be proven by: mathematical proofs, audits, reviews by security experts, mass adoption
* be tested using independently generated test vectors from well-established reference implementations as well as available test vectors in relevant specifications

## List of Algorithms

| Type | Name | Feature | Spec/RFC | Rust Source | Test Source | Rating* |
| - | - | - | - | - | - | - |
| ciphers     | AES-256-GCM        | [`aes`](/src/ciphers/aes.rs)        | [spec][AES-GCM-SPEC]       | `aes-gcm`          | [nist][AES-GCM-TEST]     | ★★★☆☆ |
| ciphers     | AES-KW        | [`aes-kw`](/src/ciphers/aes_kw.rs)        | [spec][AES-GCM-SPEC]       | `aes-crate`          | [nist][AES-GCM-TEST]     | ★★★☆☆ |
| ciphers     | XCHACHA20-POLY1305 | [`chacha`](/src/ciphers/chacha.rs)  | [rfc][XCHACHA-RFC]         | `chacha20poly1305` | [official][XCHACHA-TEST] | ★★★★★ |
| ciphers     | AES-CBC | [`aes-cbc`](/src/aes_cbc.rs) | [rfc](https://tools.ietf.org/html/rfc7518) | `crypto.rs` | [official](https://tools.ietf.org/html/rfc7518#appendix-B) | ☆☆☆☆☆ |
| hashes       | BLAKE2b-160        | [`blake2b`](/src/hashes/blake2b.rs) | [rfc][BLAKE2B-RFC]         | `blake2`           | [official][BLAKE2B-TEST] | ★★★★☆ |
| hashes       | BLAKE2b-256        | [`blake2b`](/src/hashes/blake2b.rs) | [rfc][BLAKE2B-RFC]         | `blake2`           | [official][BLAKE2B-TEST] | ★★★★☆ |
| hashes       | CURL-P             | [`curl-p`](/src/hashes/ternary/curl_p/mod.rs)   | [rfc][CURL-RFC]            | `bee-ternary`      | official                 | ★★☆☆☆ |
| hashes       | SHA2-256           | [`sha`](/src/hashes/sha.rs)         | [spec][SHA2-SPEC]          | `sha2`             | [nist][SHA2-TEST]        | ★★★★★ |
| hashes       | SHA2-384           | [`sha`](/src/hashes/sha.rs)         | [spec][SHA2-SPEC]          | `sha2`             | [nist][SHA2-TEST]        | ★★★★★ |
| hashes       | SHA2-512           | [`sha`](/src/hashes/sha.rs)         | [spec][SHA2-SPEC]          | `sha2`             | [nist][SHA2-TEST]        | ★★★★★ |
| keys | X25519 | [`x25519`](/src/x25519.rs) | [RFC7748](https://tools.ietf.org/html/rfc7748) | [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) | official | ★★★★★ |
| keys | PBKDF2-HMAC-SHA256 | [`pbkdf`](/src/keys/pbkdf.rs)       | [rfc][PBKDF-RFC]           | `pbkdf2`           | self                     | ★★★★☆ |
| keys | PBKDF2-HMAC-SHA384 | [`pbkdf`](/src/keys/pbkdf.rs)       | [rfc][PBKDF-RFC]           | `pbkdf2`           | self                     | ★★★★☆ |
| keys | PBKDF2-HMAC-SHA512 | [`pbkdf`](/src/keys/pbkdf.rs)       | [rfc][PBKDF-RFC]           | `pbkdf2`           | self                     | ★★★★☆ |
| keys | BIP-39             | [`bip39`](/src/keys/bip39.rs)            | [rfc][BIP39-RFC]           | `crypto.rs`        | [multilang][BIP39-TEST]  | ★★☆☆☆ |
| keys | SLIP-10            | [`slip10`]()                    | [rfc][SLIP10-RFC]          | `crypto.rs`    | self                     | ★★☆☆☆ |
| macs        | HMAC-SHA2-256      | [`hmac`](/src/macs/hmac.rs)         | [rfc][HMAC-RFC]            | `hmac`             | [official][HMAC-TEST]    | ★★★★☆ |
| macs        | HMAC-SHA2-384      | [`hmac`](/src/macs/hmac.rs)         | [rfc][HMAC-RFC]            | `hmac`             | [official][HMAC-TEST]    | ★★★★☆ |
| macs        | HMAC-SHA2-512      | [`hmac`](/src/macs/hmac.rs)         | [rfc][HMAC-RFC]            | `hmac`             | [official][HMAC-TEST]    | ★★★★☆ |
| signatures  | Ed25519            | [`ed25519`](/src/signatures/ed25519.rs)        | [rfc (draft)][ED25519-RFC] | `ed25519-zebra`    | extended                 | ★★★★☆ |
| utility    |  RANDOM                  | [`random`](/src/utils/rand.rs)              |                            | `getrandom`        | math                     | ★★★★★ |


\* We have chosen a fully arbitrary rating for each algorithm based on how we generally feel about them.

### Usage
`Cargo.toml`
```

[dependencies.iota-crypto]
git = "https://github.com/iotaledger/crypto.rs"
# be sure to grab the latest github commit revision hash!!!
rev = "09ff1a94d6a87838589ccf1b874cfa3283a00f26"
features = [ "random", "ed25519", "sha", "hmac", "bip39-en" ]
version = "*"

[features]
default = [ "crypto" ]
crypto = [ "iota-crypto" ]
```

`src/main.rs`
```
use crypto::{
    ciphers::{aes, aes-kw}
    hashes::{blake2b, curl-p, sha}
    keys::{bip39, pbkdf, slip10, x25519}
    macs::hmac
    signatures::ed25519
    utils::random
}
```

### Reference
```
cargo doc --workspace --no-deps --open
```
## WARNING
This library has not yet been audited for security, so use at your own peril.
Until a formal third-party security audit has taken place, the IOTA Foundation makes no guarantees to the fitness of this library for any purposes.

As such they are to be seen as experimental and not ready for real-world applications.

Nevertheless, we are very interested in feedback about the design and implementation,
and encourage you to reach out with any concerns or suggestions you may have.

## Reviewers
Review the implementation and API seperately. Verify the dependency tree with different feature flags.

## Contributors
- Focusing on providing a variety of test vectors outweighs any concerns regarding the chosen initial implementation (such as performance).
- Review the imported code

## Community Testing of Hardware / OS
- todo Matrix of tested hardware tbd.


## Discussions
If you have questions about how to use this library, or why certain decisions were made, please [create a new discussion](https://github.com/iotaledger/crypto.rs/discussions).


## Tests

```
cargo test --lib --all --all-features --tests
```
### Doctest
We aim to supply at least one docstest for every interface, so to see real world usage consult the rustdocs.


## Bindings
Generally speaking, consuming libraries of this crate are responsible for providing their own bindings and may, if they chose, decide to expose this crates functionality.


## License
Apache 2.0

[//]: # (sources)

[AES-GCM-SPEC]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmvs.pdf
[AES-GCM-TEST]: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS

[XCHACHA-RFC]: https://tools.ietf.org/html/draft-arciszewski-xchacha-03
[XCHACHA-TEST]: https://tools.ietf.org/html/draft-arciszewski-xchacha-03#appendix-A.3

[SHA2-SPEC]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
[SHA2-TEST]: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs

[CURL-RFC]: https://github.com/iotaledger/bee-rfcs/blob/master/text/0034-ternary-hash.md

[BLAKE2B-RFC]: https://tools.ietf.org/html/rfc7693
[BLAKE2B-TEST]: https://github.com/BLAKE2/BLAKE2/tree/master/testvectors

[HMAC-RFC]: https://tools.ietf.org/html/rfc4231
[HMAC-TEST]: https://tools.ietf.org/html/rfc4231#section-4.2

[ED25519-RFC]: https://github.com/iotaledger/protocol-rfcs/pull/28

[PBKDF-RFC]: https://tools.ietf.org/html/rfc2898

[BIP39-RFC]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP39-TEST]: https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json

[SLIP10-RFC]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
