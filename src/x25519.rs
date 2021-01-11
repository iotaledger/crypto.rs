// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://tools.ietf.org/html/rfc7748
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

#![allow(non_snake_case)]

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;

type SecretKey = [u8; SECRET_KEY_LENGTH];
type PublicKey = [u8; PUBLIC_KEY_LENGTH];

static BASE_POINT: PublicKey = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// nomenclature compromise:
// RFC7748   Bernstein's 2006 paper
// scalar/u  secret/public
// X25519    Curve25519

pub fn X25519(s: &SecretKey, u: Option<&PublicKey>) -> PublicKey {
    x25519_dalek::x25519(*s, *u.unwrap_or(&BASE_POINT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn RFC7748() -> crate::Result<()> {
        struct TestVector {
            secret_a: &'static str,
            public_a: Option<&'static str>,
            secret_b: Option<&'static str>,
            public_b: &'static str,
            shared: &'static str,
        }

        let tvs = [
            // https://tools.ietf.org/html/rfc7748#section-5.2
            TestVector {
                secret_a: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                public_a: None,
                secret_b: None,
                public_b: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                shared: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            },
            TestVector {
                secret_a: "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                public_a: None,
                secret_b: None,
                public_b: "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                shared: "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            },
            // https://tools.ietf.org/html/rfc7748#section-6.1
            TestVector {
                secret_a: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                public_a: Some("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
                secret_b: Some("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
                public_b: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                shared: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            },
        ];

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
}
