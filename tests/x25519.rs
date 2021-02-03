// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "x25519")]

use crypto::x25519::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, X25519};

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
        let mut sa = [0; SECRET_KEY_LENGTH];
        hex::decode_to_slice(tv.secret_a, &mut sa as &mut [u8]).unwrap();

        let pa = if let Some(s) = tv.public_a {
            let mut pa = [0; PUBLIC_KEY_LENGTH];
            hex::decode_to_slice(s, &mut pa as &mut [u8]).unwrap();
            assert_eq!(X25519(&sa, None), pa);
            pa
        } else {
            X25519(&sa, None)
        };

        let mut pb = [0; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.public_b, &mut pb as &mut [u8]).unwrap();

        let sb = if let Some(s) = tv.secret_b {
            let mut sb = [0; PUBLIC_KEY_LENGTH];
            hex::decode_to_slice(s, &mut sb as &mut [u8]).unwrap();
            assert_eq!(X25519(&sb, None), pb);
            Some(sb)
        } else {
            None
        };

        let mut expected_shared = [0; PUBLIC_KEY_LENGTH];
        hex::decode_to_slice(tv.shared, &mut expected_shared as &mut [u8]).unwrap();

        assert_eq!(X25519(&sa, Some(&pb)), expected_shared);
        if let Some(ref sb) = sb {
            assert_eq!(X25519(sb, Some(&pa)), expected_shared);
        }
    }

    Ok(())
}
