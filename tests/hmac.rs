// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "hmac")]

use crypto::macs::hmac;

struct TestVector {
    data: &'static str,
    key: &'static str,
    mac: &'static str,
}

#[test]
#[cfg(feature = "sha")]
fn test_hmac_sha256() {
    let tvs = include!("fixtures/hmac_sha256.rs");

    for tv in tvs.iter() {
        let data = hex::decode(tv.data).unwrap();
        let key = hex::decode(tv.key).unwrap();

        let mut expected_mac = [0; 32];
        hex::decode_to_slice(tv.mac, &mut expected_mac as &mut [u8]).unwrap();

        let mut mac = [0; 32];
        hmac::HMAC_SHA256(&data, &key, &mut mac);

        assert_eq!(&mac, &expected_mac);
    }
}

#[test]
#[cfg(feature = "sha")]
fn test_hmac_sha384() {
    let tvs = include!("fixtures/hmac_sha384.rs");

    for tv in tvs.iter() {
        let data = hex::decode(tv.data).unwrap();
        let key = hex::decode(tv.key).unwrap();

        let mut expected_mac = [0; 48];
        hex::decode_to_slice(tv.mac, &mut expected_mac as &mut [u8]).unwrap();

        let mut mac = [0; 48];
        hmac::HMAC_SHA384(&data, &key, &mut mac);

        assert_eq!(&mac, &expected_mac);
    }
}

#[test]
#[cfg(feature = "sha")]
fn test_hmac_sha512() {
    let tvs = include!("fixtures/hmac_sha512.rs");

    for tv in tvs.iter() {
        let data = hex::decode(tv.data).unwrap();
        let key = hex::decode(tv.key).unwrap();

        let mut expected_mac = [0; 64];
        hex::decode_to_slice(tv.mac, &mut expected_mac as &mut [u8]).unwrap();

        let mut mac = [0; 64];
        hmac::HMAC_SHA512(&data, &key, &mut mac);

        assert_eq!(&mac, &expected_mac);
    }
}
