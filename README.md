# crypto.rs

A boundary crate of selected implementations of crypto primitives that are considered to be safe to use within the IOTA Foundation.

To be included in this list an implementation must:
* expose a minimal interface using the simplest possible types with high semantic density
* be explicit what algorithm they perform (e.g. `PBKDF_HMAC_SHA512`)
* use explicit memory allocation whenever possible and prefer `no_std`
* be proven by: mathematical proofs, audits, reviews by security experts, mass adoption
* be tested using independently generated test vectors from well-established reference implementations as well as available test vectors in relevant specifications
* We trust primary research after it has been validated, RFC's must be proven...

## List of Algorithms

| Type | Feature Flag | Spec/RFC | Rust Source | Tests | Rating* | 
| - | - | - | - | - | - | 
| cipher | [`aes`](/src/ciphers/aes.rs) | [spec](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmvs.pdf) | `aes-gcm` | [nist](ttps://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS) | ★★★☆☆ |
| cipher | [`aes-kw`](/src/aes_kw.rs) | [rfc](https://tools.ietf.org/html/rfc3394) | `crypto.rs` | [official](https://tools.ietf.org/html/rfc3394#section-4) | ☆☆☆☆☆ |
| cipher | [`chacha`](/src/ciphers/chacha.rs) | [rfc](https://tools.ietf.org/html/draft-arciszewski-xchacha-03) | `chacha20poly1305` | [official](https://tools.ietf.org/html/draft-arciszewski-xchacha-03#appendix-A.3) | ★★★★★ |
| hash | [`sha`](/src/hashes/sha.rs) | [spec](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf) | `sha2` | [nist](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs) | ★★★★★ | 
| hash | [`curl-p`](/src/hashes/curl_p.rs) | [rfc](https://github.com/iotaledger/bee-rfcs/blob/master/text/0034-ternary-hash.md) | `bee-ternary` | official | ★★☆☆☆ | 
| hash | [`blake2b`](/src/hashes/blake2b.rs) |[rfc](https://tools.ietf.org/html/rfc7693) | `blake2b_simd` | [official](https://github.com/BLAKE2/BLAKE2/tree/master/testvectors) | ★★★★☆ |
| mac | [`hmac`](/src/macs/hmac.rs) | [rfc](https://tools.ietf.org/html/rfc4231) | `hmac` | [official](https://tools.ietf.org/html/rfc4231#section-4.2) | ★★★★☆ | 
| signature | [`ed25519`]() | [rfc (draft)](https://github.com/iotaledger/protocol-rfcs/pull/28) | `ed25519-zebra` | extended |  ★★★★☆ | `ed25519` |
| derivation | [`pbkdf`]() | [rfc](https://tools.ietf.org/html/rfc6070) | `pbkdf2` | [official](https://tools.ietf.org/html/rfc6070#section-2) | ★★★★☆ |
| derivation | [`bip39`]() | [rfc](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) |`crypto.rs` | [multilang](https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json) | ★★☆☆☆ |
| derivation | [`slip10`]()*\* | [rfc](https://github.com/satoshilabs/slips/blob/master/slip-0010.md )| `stronghold.rs` | self | ★★☆☆☆ |
| utility | [`rand`]() | [spec] | `getrandom` | math | ★★★★★ |


\* We have chosen a fully arbitrary rating for each algorithm based on how we generally feel about them. 
\*\* slip10 is currently in stronghold.rs, will be ported soon.

## API
Here is a basic description of the API.

- todo

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
### Doctest
We aim to supply at least one docstest for every interface, so to see real world usage consult the rustdocs. 

## FAQ
- todo

## Bindings
- todo


## Running Tests
```
cargo test --lib --all-features
```

## License
Apache 2.0
