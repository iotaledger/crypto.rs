// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "secp256k1")]

use crypto::signatures::secp256k1_ecdsa::{PublicKey, SecretKey, Signature};

mod utils;

fn run_secp256k1_sign_verify(sk: SecretKey, pk: PublicKey) {
    assert_eq!(pk.to_bytes(), sk.public_key().to_bytes());
    let _addr = pk.to_address();

    let sk_bytes = sk.to_bytes();
    let sk2 = SecretKey::try_from_bytes(sk_bytes).unwrap();
    let sk2_bytes = sk2.to_bytes();
    assert_eq!(sk_bytes, sk2_bytes);

    let pk_bytes = pk.to_bytes();
    let pk2 = PublicKey::try_from_bytes(&pk_bytes).unwrap();
    let pk2_bytes = pk2.to_bytes();
    assert_eq!(pk_bytes, pk2_bytes);

    let msg = utils::fresh::bytestring();
    let sig = sk.sign(&msg);
    let mut sig_bytes = sig.to_bytes();
    let sig2 = Signature::try_from_bytes(&sig_bytes).unwrap();

    assert_eq!(pk, sig.verify_recover(&msg).unwrap());

    assert!(pk.verify(&sig2, &msg));
    #[cfg(feature = "rand")]
    assert!(!SecretKey::generate()
        .public_key()
        .verify(&Signature::try_from_slice(&sig_bytes).unwrap(), &msg));

    // utils::corrupt(&mut sig_bytes);
    sig_bytes[7] ^= 1;
    assert!(!pk.verify(&Signature::try_from_bytes(&sig_bytes).unwrap(), &msg));
}

#[test]
fn test_secp256k1_sign_verify() {
    use core::convert::TryInto;
    let skb = hex::decode("ea68a753b20281db2cd5084a215fdda70c7e3cf3d167575fce9b02eb1f36fe9c").unwrap();
    let sk = SecretKey::try_from_bytes((&skb[..]).try_into().unwrap()).unwrap();

    // let pkb = hex::decode("af81cf426b23df0f01c2f6acd86a7fa24cf48c1637c320e06f40dc315b597f6d6c6ccd209dfd4ea7ddb20c22b778c73dfbd44c2f7eeebed224878009fda33d16").unwrap();
    let pkb = hex::decode("02af81cf426b23df0f01c2f6acd86a7fa24cf48c1637c320e06f40dc315b597f6d").unwrap();
    let pk = PublicKey::try_from_slice(&pkb).unwrap();

    run_secp256k1_sign_verify(sk, pk);
}

#[cfg(feature = "rand")]
#[test]
fn test_secp256k1_sign_verify_random() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    run_secp256k1_sign_verify(sk, pk);
}
