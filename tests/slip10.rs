// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "slip10")]
mod test {
    use crypto::{
        keys::slip10::{Chain, Curve, Seed},
        Result,
    };

    struct TestChain {
        chain: Chain,
        chain_code: &'static str,
        private_key: &'static str,
    }

    struct TestVector {
        seed: &'static str,
        master_chain_code: &'static str,
        master_private_key: &'static str,
        chains: Vec<TestChain>,
    }

    #[test]
    fn ed25519_test_vectors() -> Result<()> {
        let tvs = include!("fixtures/slip10_ed25519.rs");

        for tv in &tvs {
            let seed = Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key(Curve::Ed25519);
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(&tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(&tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, m.secret_key().to_bytes());

            for c in tv.chains.iter() {
                let ck = seed.derive(Curve::Ed25519, &c.chain)?;

                let mut expected_chain_code = [0u8; 32];
                hex::decode_to_slice(&c.chain_code, &mut expected_chain_code as &mut [u8]).unwrap();
                assert_eq!(expected_chain_code, ck.chain_code());

                let mut expected_private_key = [0u8; 32];
                hex::decode_to_slice(&c.private_key, &mut expected_private_key as &mut [u8]).unwrap();
                assert_eq!(expected_private_key, ck.secret_key().to_bytes());
            }
        }

        Ok(())
    }
}
