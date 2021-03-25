// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "secp256k1")]

use crypto::signatures::secp256k1::{PublicKey, SecretKey};

mod utils;

#[test]
fn test_secp256k1_sign_verify() {
    let skb = hex::decode("ea68a753b20281db2cd5084a215fdda70c7e3cf3d167575fce9b02eb1f36fe9c").unwrap();
    let sk = SecretKey::from_bytes(&skb).unwrap();

    let pkb = hex::decode("af81cf426b23df0f01c2f6acd86a7fa24cf48c1637c320e06f40dc315b597f6d6c6ccd209dfd4ea7ddb20c22b778c73dfbd44c2f7eeebed224878009fda33d16").unwrap();
    let pk = PublicKey::from_bytes(&pkb).unwrap();

    assert_eq!(pk.to_bytes(), sk.public_key().to_bytes());

    let msg = utils::fresh::bytestring();
    let mut sig = sk.sign(&msg).unwrap().as_ref().to_vec();

    assert!(pk.verify(&msg, &sig).is_ok());
    assert!(SecretKey::generate().unwrap().public_key().verify(&msg, &sig).is_err());

    utils::corrupt(&mut sig);
    assert!(pk.verify(&msg, &sig).is_err());
}

#[cfg(feature = "random")]
#[test]
fn test_secp256k1_sign_verify_random() {
    let sk = SecretKey::generate().unwrap();
    let pk = sk.public_key();

    let msg = utils::fresh::bytestring();
    let mut sig = sk.sign(&msg).unwrap().as_ref().to_vec();

    assert!(pk.verify(&msg, &sig).is_ok());
    assert!(SecretKey::generate().unwrap().public_key().verify(&msg, &sig).is_err());

    utils::corrupt(&mut sig);
    assert!(pk.verify(&msg, &sig).is_err());
}
