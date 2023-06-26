// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "secp256k1")]

use crypto::signatures::secp256k1_ecdsa::{PublicKey, SecretKey, Signature};

mod utils;

fn run_secp256k1_sign_verify(sk: SecretKey, pk: PublicKey) {
    assert_eq!(pk.to_bytes(), sk.public_key().to_bytes());
    let _addr = pk.to_evm_address();

    let sk_bytes = sk.to_bytes();
    let sk2 = SecretKey::try_from_bytes(&sk_bytes).unwrap();
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

#[test]
fn test_secp256k1_public_key_bytes() {
    let mut sk_bytes = [0_u8; 32];
    let mut pk_bytes = [0_u8; 33];
    sk_bytes[0] += 1;
    let sk = SecretKey::try_from_bytes(&sk_bytes).unwrap();
    let pk = sk.public_key();
    pk_bytes.copy_from_slice(&pk.to_bytes());
    assert_eq!(2, pk_bytes[0]);
    pk_bytes[0] = 5;
    // This is a SEC1 Compact form of the same public key. It is forbidden
    let pk2 = PublicKey::try_from_bytes(&pk_bytes);
    assert!(pk2.is_err());
}

#[test]
fn test_ord() {
    let b111 = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    ];
    let b112 = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2,
    ];
    let b121 = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1,
    ];
    let b211 = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    ];
    let beff = [
        0x2d, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2e, 0xfc, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 3,
    ];
    let bfef = [
        0x2e, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2d, 0xfc, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 3,
    ];
    let bffe = [
        0x2e, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2e, 0xfc, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2,
    ];
    let bfff = [
        0x2e, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2e, 0xfc, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 3,
    ];
    let bs = [b111, b112, b121, b211, beff, bfef, bffe, bfff];
    for i in 0..bs.len() - 1 {
        for j in i + 1..bs.len() {
            let sigi = Signature::try_from_bytes(&bs[i]).unwrap();
            let sigj = Signature::try_from_bytes(&bs[j]).unwrap();
            assert!(sigi < sigj);
            assert!(bs[i] < bs[j]);
        }
    }
    for b in bs {
        let sig = Signature::try_from_bytes(&b).unwrap();
        assert_eq!(b, sig.to_bytes());
    }
}
