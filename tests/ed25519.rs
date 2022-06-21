// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "ed25519")]

mod utils;

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

use crypto::signatures::ed25519::{PublicKey, SecretKey, Signature};

#[test]
fn test_zip215() -> crypto::Result<()> {
    struct TestVector {
        public_key: &'static str,
        signature: &'static str,
    }
    let tvs = include!("fixtures/zip215.rs");
    let msg = "Zcash";
    let ms = msg.as_bytes();

    for tv in tvs.iter() {
        let mut pkb = [0; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
        let pk = PublicKey::try_from_bytes(pkb)?;

        let mut sigb = [0; SIGNATURE_LENGTH];
        hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
        let sig = Signature::from_bytes(sigb);

        assert!(PublicKey::verify(&pk, &sig, ms));
    }

    Ok(())
}

#[test]
fn test_malleability() -> crypto::Result<()> {
    // https://tools.ietf.org/html/rfc8032#section-5.1.7 adds an additional test
    // that s be in [0, order). This prevents someone from adding a multiple of
    // order to s and obtaining a second valid sig for the same message.
    let ms = [0x54, 0x65, 0x73, 0x74];

    let sigb = [
        0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a, 0x0f, 0x2d, 0xb8, 0xb0, 0xcd, 0x78, 0x30,
        0x40, 0x60, 0x9a, 0x8b, 0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27, 0x77, 0x4a, 0xb0, 0x67, 0x65, 0x4b, 0xce,
        0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d, 0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57,
        0x33, 0x36, 0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
    ];
    let sig = Signature::from_bytes(sigb);

    let pkb = [
        0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5, 0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4,
        0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa,
    ];
    let pk = PublicKey::try_from_bytes(pkb)?;

    assert!(!PublicKey::verify(&pk, &sig, &ms));

    Ok(())
}

#[test]
fn test_golden() -> crypto::Result<()> {
    struct TestVector {
        secret_key: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }
    let tvs = include!("fixtures/ed25519_sign.rs");
    for tv in tvs.iter() {
        let mut skb = [0; SECRET_KEY_LENGTH];
        hex::decode_to_slice(tv.secret_key, &mut skb as &mut [u8]).unwrap();
        let sk = SecretKey::from_bytes(skb);
        assert_eq!(skb, sk.to_bytes());

        let mut pkb = [0; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
        assert_eq!(pkb, sk.public_key().to_bytes());
        let pk = PublicKey::try_from_bytes(pkb)?;
        assert_eq!(pkb, pk.to_bytes());

        let msg = hex::decode(tv.message).unwrap();

        let mut sigb = [0; SIGNATURE_LENGTH];
        hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
        assert_eq!(sigb, sk.sign(&msg).to_bytes());
        let sig = Signature::from_bytes(sigb);
        assert!(PublicKey::verify(&pk, &sig, &msg));
        #[cfg(feature = "random")]
        assert!(!PublicKey::verify(&SecretKey::generate()?.public_key(), &sig, &msg));
    }

    Ok(())
}

struct TestVector {
    secret_key: &'static str,
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
}

#[test]
fn test_eq_ord() -> crypto::Result<()> {
    let public_key = "f24a3306ce8698c6bafb11f465f2be695f220fddbca69ca9cf133757c9c29378";
    let public_key_different = "82eeba00688da228b83bbe32d6c2e2d548550ab3c6e30752d9fe2617e89f554d";

    let mut pkb = [0; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(public_key, &mut pkb as &mut [u8]).unwrap();
    let pk = PublicKey::try_from_bytes(pkb)?;

    let mut pkb_eq = [0; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(public_key, &mut pkb_eq as &mut [u8]).unwrap();
    let pk_eq = PublicKey::try_from_bytes(pkb_eq)?;

    let mut pkb_diff = [0; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(public_key_different, &mut pkb_diff as &mut [u8]).unwrap();
    let pk_diff = PublicKey::try_from_bytes(pkb_diff)?;

    assert!(pk == pk_eq);
    assert!(pk != pk_diff);
    assert!(pk > pk_diff);

    Ok(())
}

#[test]
fn test_vectors() -> crypto::Result<()> {
    let tvs = include!("fixtures/ed25519.rs");

    for tv in tvs.iter() {
        let mut skb = [0; SECRET_KEY_LENGTH];
        hex::decode_to_slice(tv.secret_key, &mut skb as &mut [u8]).unwrap();
        let sk = SecretKey::from_bytes(skb);
        assert_eq!(skb, sk.to_bytes());

        let mut pkb = [0; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
        assert_eq!(pkb, sk.public_key().to_bytes());
        let pk = PublicKey::try_from_bytes(pkb)?;
        assert_eq!(pkb, pk.to_bytes());

        let msg = hex::decode(tv.message).unwrap();

        let mut sigb = [0; SIGNATURE_LENGTH];
        hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
        assert_eq!(sigb, sk.sign(&msg).to_bytes());
        let sig = Signature::from_bytes(sigb);
        assert!(PublicKey::verify(&pk, &sig, &msg));
        #[cfg(feature = "random")]
        assert!(!PublicKey::verify(&SecretKey::generate()?.public_key(), &sig, &msg));

        utils::corrupt(&mut sigb);
        let incorrect_sig = Signature::from_bytes(sigb);
        assert!(!PublicKey::verify(&pk, &incorrect_sig, &msg));
    }

    Ok(())
}

#[cfg(feature = "random")]
#[test]
fn test_generate() -> crypto::Result<()> {
    let sk = SecretKey::generate()?;
    let msg = utils::fresh::bytestring();

    let sig = sk.sign(&msg);

    assert!(PublicKey::verify(&sk.public_key(), &sig, &msg));
    assert!(!PublicKey::verify(&SecretKey::generate()?.public_key(), &sig, &msg));

    let mut sigb = sig.to_bytes();
    utils::corrupt(&mut sigb);
    let incorrect_sig = Signature::from_bytes(sigb);
    assert!(!PublicKey::verify(&sk.public_key(), &incorrect_sig, &msg));

    Ok(())
}
