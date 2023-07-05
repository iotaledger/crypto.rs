// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "keccak")]

use crypto::hashes::keccak::{keccak256, KECCAK256_LEN};

struct TestVector {
    msg: &'static str,
    digest: &'static str,
}

#[test]
fn test_keccak256() {
    let tvs = include!("fixtures/keccak_256.rs");

    for tv in tvs.iter() {
        let msg = hex::decode(tv.msg).unwrap();

        let mut expected_digest = [0; KECCAK256_LEN];
        hex::decode_to_slice(tv.digest, &mut expected_digest as &mut [u8]).unwrap();

        let mut digest = [0; KECCAK256_LEN];
        keccak256(&msg, &mut digest);

        assert_eq!(&digest, &expected_digest);
    }
}
