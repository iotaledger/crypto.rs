// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "ed25519")]

mod utils;

pub const SECRET_KEY_LENGTH: usize = 32;
pub const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 32;
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
        let mut pkb = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
        let pk = PublicKey::from_compressed_bytes(pkb)?;

        let mut sigb = [0; SIGNATURE_LENGTH];
        hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
        let sig = Signature::from_bytes(sigb);

        assert!(PublicKey::verify(&pk, &sig, &ms));
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
    let pk = PublicKey::from_compressed_bytes(pkb)?;

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
        let sk = SecretKey::from_le_bytes(skb)?;
        assert_eq!(skb, sk.to_le_bytes());

        let mut pkb = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
        assert_eq!(pkb, sk.public_key().to_compressed_bytes());
        let pk = PublicKey::from_compressed_bytes(pkb)?;
        assert_eq!(pkb, pk.to_compressed_bytes());

        let msg = hex::decode(tv.message).unwrap();

        let mut sigb = [0; SIGNATURE_LENGTH];
        hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
        assert_eq!(sigb, sk.sign(&msg).to_bytes());
        let sig = Signature::from_bytes(sigb);
        assert!(PublicKey::verify(&pk, &sig, &msg));
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

    let mut pkb = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(public_key, &mut pkb as &mut [u8]).unwrap();
    let pk = PublicKey::from_compressed_bytes(pkb)?;

    let mut pkb_eq = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(public_key, &mut pkb_eq as &mut [u8]).unwrap();
    let pk_eq = PublicKey::from_compressed_bytes(pkb_eq)?;

    let mut pkb_diff = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(public_key_different, &mut pkb_diff as &mut [u8]).unwrap();
    let pk_diff = PublicKey::from_compressed_bytes(pkb_diff)?;

    assert!(pk == pk_eq);
    assert!(pk != pk_diff);
    assert!(pk > pk_diff);
    assert!(!(pk > pk_eq));

    Ok(())
}

#[test]
fn test_vectors() -> crypto::Result<()> {
    let tvs = [
        // generated using: utils/test_vectors/py/main.py
        TestVector {
            secret_key: "f22d2d57c1a188e362f38c6789948df333e37ea3276357a1169cff12a2b7d100",
            public_key: "f24a3306ce8698c6bafb11f465f2be695f220fddbca69ca9cf133757c9c29378",
            message: "3a6e84dd6ccefaa125f9913020ce9680b41cbe9b685022b46011ce2f4a7a62d465a2e1a7519a169f9c2fa07ffcab91be1ac9aa2f9e4e1c3143cacc006b00fad92e9a66648620d665e3f834fa924519b7aaafe5cd84f81a98da343e15549dd2d6fcb1969916f3d6d1de55207452d704",
            signature: "e197a50432c58b2a6a7e9c5d3b00c25c1e1b415bb9f30613efaf9d4ab61ad9654ebb8a27555eaf984d6492480e5e0e70abe814ad3596536f0c9bfddc43a63802",
        },
        TestVector {
            secret_key: "7e828a3c369f1d963685aae2354ab7f3509bed9e6244a7d4c370daccb37ca606",
            public_key: "82eeba00688da228b83bbe32d6c2e2d548550ab3c6e30752d9fe2617e89f554d",
            message: "a4f664a6bd9f9ab149c69fba1fb0df33908dacef11571be476bf71dbd9e1262c2591f0fe86c6b0a35b2cd8f08d41c23f979678be69c92a50491433eb43",
            signature: "e4c5ff2662d13452356078e71e7587d589474c15316d2e1a036be9a4a5e8a9f58f451083a984bf936583da504be8deaf2ba27eca1f9fadc266fa1b0e4d05b002",
        },
        TestVector {
            secret_key: "571ec49b416372c19b71f9949546eaa489816f20cda32c59fcaaa7fe28317a30",
            public_key: "3b20f8c1f07e28a1f8346d01a65750d0e0c34f314c4079e7ede7df5a5751aca3",
            message: "3697b7d56247f4a086cee766ec0ed807e1097b853a1e5f81a9081a869aff9f4642d3e9147d82c778526226c3f342b06e1c4e37b13344f42354f73e2366855aa7726693c0cabd6fd9027ebffe7667a2c549a4357a9e8b7e387e9e4ebd504e3ec52358d35a133a2a4185e4de5d7a057c4d6964d44b1a0678a8d9c9c8932bd2a4af2609d01339be6aae02c7510ec0df22e8aa95a846c1bbe0f1f5ba2cad9322a310a94b811fce132b4ddc1628c7e135a159f15b5ad0c14171e94a2891c2bb31220d75084cba46890288733676aaf835",
            signature: "cbbcdefc4e8e38788c5c41069c1f381820a4b17c62a67f9fd792f9ea5b10b6bca24b65e92b2a15a2c831548c5d44ec70e59a6e11ec9a993a98414d00b00aea07",
        },
    ];

    for tv in tvs.iter() {
        let mut skb = [0; SECRET_KEY_LENGTH];
        hex::decode_to_slice(tv.secret_key, &mut skb as &mut [u8]).unwrap();
        let sk = SecretKey::from_le_bytes(skb)?;
        assert_eq!(skb, sk.to_le_bytes());

        let mut pkb = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
        assert_eq!(pkb, sk.public_key().to_compressed_bytes());
        let pk = PublicKey::from_compressed_bytes(pkb)?;
        assert_eq!(pkb, pk.to_compressed_bytes());

        let msg = hex::decode(tv.message).unwrap();

        let mut sigb = [0; SIGNATURE_LENGTH];
        hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
        assert_eq!(sigb, sk.sign(&msg).to_bytes());
        let sig = Signature::from_bytes(sigb);
        assert!(PublicKey::verify(&pk, &sig, &msg));
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
