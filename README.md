# crypto.rs

A boundary crate of selected implementations of crypto primitives that are
considered to be safe to use within the IOTA Foundation.

To be included in this list an implementation must:
* be open source
* be proven by: audits, reviews by security experts, mass adoption
* use explicit memory allocation, preferably in-place

## WARNING
This library has not yet been audited for security, so use at your own peril.
Until a formal third-party security audit has taken place, the IOTA Foundation
makes no guarantees to the fitness of this library for any purposes.

As such they are to be seen as experimental and not ready for real-world applications.

Nevertheless, we are very interested in feedback about the design and implementation,
and encourage you to reach out with any concerns or suggestions you may have.

## API Reference
```
cargo doc --workspace --no-deps --open
```

## Running Tests
```
cargo test --all
```
