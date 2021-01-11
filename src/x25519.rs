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
            // generated using: utils/test_vectors/nacl/x25519.c
            TestVector {
                secret_a: "b1dc0c398e48991fdaee9dbe910e13935b6fb7ce4b9b89b91274203829c0fcc8",
                public_a: Some("0dd2d1ce9f5ef0d929806b126bc8bc31d79ac531e087030ba0974f6ed4d14a3a"),
                secret_b: Some("a044dec6e938b1ad0b9a43e7183b4a59435401c6dbcab27e69e9d2f9c90d20fa"),
                public_b: "1bb8dc057eeb9b21e1d84a495c64db8324fc483f3e78d3ecb87aa58c247ec217",
                shared: "acbb80729ed87c77770f38cd9a136043ee9273467a9cbaca4d2f98eabc5bc60f",
            },
            TestVector {
                secret_a: "ec861300c7baafe1cfdd126f9ca1980083f39a84accc74e168d158ef27fbe2ce",
                public_a: Some("44f2db0e3f58ddf6cdbc1ba42fdaf2136cb6775eec990ff9e2469edb7ed4467d"),
                secret_b: Some("fe4862e2057b1923ca0a4e394e0b1eb9d5725d4f9896eda1943df795d0b01e6e"),
                public_b: "676c1612f2b43bb49b9725bf490be405d6ee38c8a8d5ee1438b03f3ad732f464",
                shared: "68a1f097fe65186ebe0101f0b0add0fcee965b9356c3dd2ce20e51d2779ad277",
            },
            TestVector {
                secret_a: "0cc66d9de967e71150708e29a4b1ebd3ee32ab0f140b15cc7ed6b43ecc124390",
                public_a: Some("7f4e11a110c4c0ecbdf52408474f7b837808b9bb1d2ad03178608fb12cfb8f45"),
                secret_b: Some("3d9840467683b69871ba6ef087de87cebde227254a921aa4f7be8fad9972bcb6"),
                public_b: "1b93cb57d71100214da77402dafe60852129e03176deb61ac62bccca830e2569",
                shared: "379ca0635ef0aa740e7bff5f8d9d1acde5a4dbe751bb0ed6f6ae9d4fdb75aa58",
            },
            TestVector {
                secret_a: "47edc08cc0da0cac740f2aff0a5d70d2885bfe5a6cff34addfe50515a5b8e585",
                public_a: Some("7e03563ab52a78d876dddcd47e395ae3cf4e822f18924b960dc2dbba5ca61975"),
                secret_b: Some("dd5e9c939f6c534cce154e9c29603ace4da55ff8aff0a53a40ae41aecfe3a098"),
                public_b: "5de001212b7ab8a746fcd7652d54ed3cff08791ddf55654260b06a70ead15921",
                shared: "08aaf881d241bc416d2b6d169e5ac9faf5337ea2321701e14b6ac8704b8a2a37",
            },
            TestVector {
                secret_a: "ae19ab4605a3acd6e0e304830e2aec2862ba472823c8aed7a4810ccdceb064d4",
                public_a: Some("bb905089d72343967cf4cd6574ff183b4f46d68307c1cd87ec684c76a820790f"),
                secret_b: Some("0a7c555e9bf6238d0e528029fc539bef2f750f2e9a0ffac2adac8aca8621cf6d"),
                public_b: "8cb6114b9c0a7568cb5a7965a10e31f1205c182065e63a01906e2411ddc7b876",
                shared: "099846c40d333a28d5a5fc85d30eaf5f432ea2c49b1a81ee660b3c96de68d83c",
            },
            TestVector {
                secret_a: "b306b5de24f12120a63fc564fd607a4b72aa4c7fcdf9db897e33ca251c9cf2f0",
                public_a: Some("fc61c357cd30ec736bece9b227b73eee40d8115a7006881398c2e0c3a1a39700"),
                secret_b: Some("e23f209368f57ffc01f120aeba3fa7ec8a11a94b1c21a79b8ecac923dd59c814"),
                public_b: "dc074670987767d0b50c97f76d013ac0d02c6c6c52b226a0472b89dcfe9ddd22",
                shared: "93137d5155b4fd29d50d125df01c38bf4a9eb158bff4d0fe02746d6a7096ea74",
            },
            TestVector {
                secret_a: "9ad48ae11e4d3d7e6ad77cd59ccdeea998674103276f23b93661a086f0a709b7",
                public_a: Some("61a895837375649d3860804b9500c4d815e7f0e0bfaa328f625f15b829108b2d"),
                secret_b: Some("a88c291d11f66371da408c7877246033ea0a77fee9f0269d6e0848550634007e"),
                public_b: "cf54f41ca6bcb3f58c3b6da74eb4fa717f6381be352724fa0965556850492f22",
                shared: "39c97ef0d647890013f4cec1dbd8375ac2a6784d7cb7ad266f7c11805196e330",
            },
            TestVector {
                secret_a: "1fe676600894cd6cbcf48e75c362cf05aefda45ea8b92c2bffbdf9ae76046580",
                public_a: Some("60c1898f99e38d8799b1e280146961dff57b25129d2c97db4a39b2c97ca1b551"),
                secret_b: Some("c3899ed164c9e6b23a049f0453f4caa913056cdf6e196105614b6e371c274465"),
                public_b: "bf16af6620f165ea8fd8a972a0b691b34a36b7665f8d5547dfad483c4c4cda5b",
                shared: "79a778467ff7967844f23363f64d32feac3b8e7b88994abf706258e254063f7f",
            },
            TestVector {
                secret_a: "f754900c1a2aa97e772572ed4d3d32309303056c6ddb9a371855ddc8c153bcc8",
                public_a: Some("ef70334728de13158fdaa795d330cb120454d12c6c61545481dc78a874135d26"),
                secret_b: Some("d63573f0d62ad14c66707cd35d4d42242ffa43ac38abae835ac0cccdb7fee1ee"),
                public_b: "f9050296717ec7e7e9dd1bd7365be98227430f07032c2e7386722d66dc13571e",
                shared: "55624b2019e85f111d8064a31132277fdc28f0f8ab519052f890bda7cda26329",
            },
            TestVector {
                secret_a: "02dadfa737f0c950bd3876fab9b55d70cd162d8d337c487e86725dc3d2086aa4",
                public_a: Some("cd93b9115a7be152bf672d6dfa8cccb58c36e74718c40cfb58bda37c5085573f"),
                secret_b: Some("fcb2694cba1b0864015159ff9c3d309efce3bfc8808cc2fd0f60eb0c1d5e9a39"),
                public_b: "6634c3550e75a1e9d00bb9d54a83449f1bf1fc131b29e4258f17e73e73b85109",
                shared: "b5cd132f075f2a30d584d66b7d735bc3627405a2d1a5ea03f3e22c2d4ccb7867",
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
