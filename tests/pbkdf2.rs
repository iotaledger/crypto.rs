// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "pbkdf2")]

use core::convert::TryInto;

use crypto::keys::pbkdf::{PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512};

struct TestVector {
    password: &'static str,
    salt: &'static str,
    c: usize,
    dk: &'static str,
}

#[test]
fn test_pbkdf2_hmac_sha256() {
    let tvs = include!("fixtures/pbkdf2_hmac_sha256.rs");

    for tv in tvs.iter() {
        let password = hex::decode(tv.password).unwrap();
        let salt = hex::decode(tv.salt).unwrap();
        let mut expected_dk = [0; 32];
        hex::decode_to_slice(tv.dk, &mut expected_dk).unwrap();

        let mut dk = [0; 32];
        let rounds = (tv.c as u32).try_into().unwrap();
        PBKDF2_HMAC_SHA256(&password, &salt, rounds, &mut dk);
        assert_eq!(dk, expected_dk);
    }
}

#[test]
fn test_pbkdf2_hmac_sha384() {
    let tvs = include!("fixtures/pbkdf2_hmac_sha384.rs");

    for tv in tvs.iter() {
        let password = hex::decode(tv.password).unwrap();
        let salt = hex::decode(tv.salt).unwrap();
        let mut expected_dk = [0; 48];
        hex::decode_to_slice(tv.dk, &mut expected_dk).unwrap();

        let mut dk = [0; 48];
        let rounds = (tv.c as u32).try_into().unwrap();
        PBKDF2_HMAC_SHA384(&password, &salt, rounds, &mut dk);
        assert_eq!(dk, expected_dk);
    }
}

#[test]
fn test_pbkdf2_hmac_sha512() {
    let tvs = include!("fixtures/pbkdf2_hmac_sha512.rs");

    for tv in tvs.iter() {
        let password = hex::decode(tv.password).unwrap();
        let salt = hex::decode(tv.salt).unwrap();
        let mut expected_dk = [0; 64];
        hex::decode_to_slice(tv.dk, &mut expected_dk).unwrap();

        let mut dk = [0; 64];
        let rounds = (tv.c as u32).try_into().unwrap();
        PBKDF2_HMAC_SHA512(&password, &salt, rounds, &mut dk);
        assert_eq!(dk, expected_dk);
    }
}
