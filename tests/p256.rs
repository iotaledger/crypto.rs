// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "p256")]

use crypto::signatures::p256::{PublicKey, SecretKey};

mod utils;

struct TestVector {
    message: &'static [u8],
    x: &'static str,
    ux: &'static str,
    uy: &'static str,
    r: &'static str,
    s: &'static str,
}

#[test]
fn test_p256_test_vectors() {
    let tvs = include!("fixtures/p256.rs");

    for tv in tvs.iter() {
        let skb = hex::decode(tv.x).unwrap();
        let sk = SecretKey::from_bytes(&skb).unwrap();
        assert_eq!(&sk.to_bytes()[..], &skb[..]);

        let ux = hex::decode(tv.ux).unwrap();
        let uy = hex::decode(tv.uy).unwrap();
        let pkb = [ux, uy].concat();
        let pk = PublicKey::from_bytes(&pkb).unwrap();
        assert_eq!(&pk.to_bytes()[..], &pkb);
        assert_eq!(&pk.to_bytes()[..], &sk.public_key().to_bytes()[..]);

        let out = sk.sign(tv.message).unwrap();
        let r = hex::decode(tv.r).unwrap();
        let s = hex::decode(tv.s).unwrap();
        let sig = [r, s].concat();
        assert_eq!(out.as_ref(), &sig[..]);
        assert!(pk.verify(tv.message, out.as_ref()).is_ok());
    }
}

#[cfg(feature = "random")]
#[test]
fn test_p256_sign_verify_random() {
    let sk = SecretKey::generate().unwrap();
    let pk = sk.public_key();

    let msg = utils::fresh::bytestring();
    let mut sig = sk.sign(&msg).unwrap().as_ref().to_vec();

    assert!(pk.verify(&msg, &sig).is_ok());
    assert!(SecretKey::generate().unwrap().public_key().verify(&msg, &sig).is_err());

    utils::corrupt(&mut sig);
    assert!(pk.verify(&msg, &sig).is_err());
}
