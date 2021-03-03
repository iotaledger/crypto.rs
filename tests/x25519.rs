// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "x25519")]

use crypto::keys::x25519::{PublicKey, SecretKey};

struct TestVector {
    secret_a: &'static str,
    public_a: Option<&'static str>,
    secret_b: Option<&'static str>,
    public_b: &'static str,
    shared: &'static str,
}

#[test]
fn test_x25519_rfc7748() -> crypto::Result<()> {
    let tvs = include!("fixtures/x25519.rs");

    for tv in tvs.iter() {
        let secret_a: SecretKey = {
            let bytes = hex::decode(tv.secret_a).unwrap();
            SecretKey::from_bytes(&bytes)?
        };

        let public_a: Option<PublicKey> = {
            let bytes = tv.public_a.map(hex::decode).transpose().unwrap();
            bytes.map(|bytes| PublicKey::from_bytes(&bytes)).transpose()?
        };

        let secret_b: Option<SecretKey> = {
            let bytes = tv.secret_b.map(hex::decode).transpose().unwrap();
            bytes.map(|bytes| SecretKey::from_bytes(&bytes)).transpose()?
        };

        let public_b: PublicKey = {
            let bytes = hex::decode(tv.public_b).unwrap();
            PublicKey::from_bytes(&bytes)?
        };

        let expected: Vec<u8> = hex::decode(tv.shared).unwrap();

        if let Some(public_a) = public_a {
            assert_eq!(secret_a.public_key().to_bytes(), public_a.to_bytes());
        }

        if let Some(ref secret_b) = secret_b {
            assert_eq!(secret_b.public_key().to_bytes(), public_b.to_bytes());
        }

        assert_eq!(secret_a.diffie_hellman(&public_b).to_bytes(), &expected[..],);

        if let Some(ref secret_b) = secret_b {
            assert_eq!(
                secret_b.diffie_hellman(&secret_a.public_key()).to_bytes(),
                &expected[..],
            );
        }
    }

    Ok(())
}
