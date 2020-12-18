// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sha")]

use crypto::hashes::sha::{SHA256, SHA256_LEN, SHA384, SHA384_LEN, SHA512, SHA512_LEN};

struct TestVector {
    msg: &'static str,
    digest: &'static str,
}

#[test]
fn test_sha256() {
    let tvs = include!("fixtures/sha2_256.rs");

    for tv in tvs.iter() {
        let msg = hex::decode(tv.msg).unwrap();

        let mut expected_digest = [0; SHA256_LEN];
        hex::decode_to_slice(tv.digest, &mut expected_digest as &mut [u8]).unwrap();

        let mut digest = [0; SHA256_LEN];
        SHA256(&msg, &mut digest);

        assert_eq!(&digest, &expected_digest);
    }
}

#[test]
fn test_sha384() {
    let tvs = include!("fixtures/sha2_384.rs");

    for tv in tvs.iter() {
        let msg = hex::decode(tv.msg).unwrap();

        let mut expected_digest = [0; SHA384_LEN];
        hex::decode_to_slice(tv.digest, &mut expected_digest as &mut [u8]).unwrap();

        let mut digest = [0; SHA384_LEN];
        SHA384(&msg, &mut digest);

        assert_eq!(&digest, &expected_digest);
    }
}

#[test]
fn test_sha512() {
    let tvs = include!("fixtures/sha2_512.rs");

    for tv in tvs.iter() {
        let msg = hex::decode(tv.msg).unwrap();

        let mut expected_digest = [0; SHA512_LEN];
        hex::decode_to_slice(tv.digest, &mut expected_digest as &mut [u8]).unwrap();

        let mut digest = [0; SHA512_LEN];
        SHA512(&msg, &mut digest);

        assert_eq!(&digest, &expected_digest);
    }
}
