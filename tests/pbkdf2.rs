// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "pbkdf")]

use crypto::kdfs::pbkdf::PBKDF2_HMAC_SHA512;

struct TestVector {
    password: &'static str,
    salt: &'static str,
    c: usize,
    dk: &'static str,
}

#[test]
#[cfg(all(feature = "hmac", feature = "sha"))]
fn test_PBKDF2_HMAC_SHA512() {
    let tvs = include!("fixtures/pbkdf2_hmac_sha512.rs");

    for tv in tvs.iter() {
        let password = hex::decode(tv.password).unwrap();
        let salt = hex::decode(tv.salt).unwrap();
        let mut expected_dk = [0; 64];
        hex::decode_to_slice(tv.dk, &mut expected_dk).unwrap();

        let mut dk = [0; 64];
        PBKDF2_HMAC_SHA512(&password, &salt, tv.c, &mut dk).unwrap();
        assert_eq!(dk, expected_dk);
    }
}
