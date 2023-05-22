// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "slip10")]
mod slip10 {
    #![allow(clippy::identity_op)]

    use crypto::{
        keys::slip10::{Chain, Hardened, Seed},
        Result,
    };

    struct TestChain {
        chain: Chain<Hardened<u32>>,
        chain_code: &'static str,
        private_key: &'static str,
    }

    struct TestVector {
        seed: &'static str,
        master_chain_code: &'static str,
        master_private_key: &'static str,
        chains: Vec<TestChain>,
    }

    #[cfg(feature = "ed25519")]
    fn run_ed25519_test_vectors(tvs: &[TestVector]) -> Result<()> {
        use crypto::signatures::ed25519;

        for tv in tvs {
            let seed = Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key::<ed25519::SecretKey>();
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, *m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, *m.secret_key().to_bytes());

            for c in tv.chains.iter() {
                let ck = seed.derive_hardened::<ed25519::SecretKey>(&c.chain);

                let mut expected_chain_code = [0u8; 32];
                hex::decode_to_slice(c.chain_code, &mut expected_chain_code as &mut [u8]).unwrap();
                assert_eq!(expected_chain_code, *ck.chain_code());

                let mut expected_private_key = [0u8; 32];
                hex::decode_to_slice(c.private_key, &mut expected_private_key as &mut [u8]).unwrap();
                assert_eq!(expected_private_key, *ck.secret_key().to_bytes());
            }
        }

        Ok(())
    }

    #[cfg(feature = "secp256k1")]
    fn run_secp256k1_test_vectors(tvs: &[TestVector]) -> Result<()> {
        use crypto::keys::slip10::Segment;
        use crypto::signatures::secp256k1_ecdsa;

        for tv in tvs {
            let seed = Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key::<secp256k1_ecdsa::SecretKey>();
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, *m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, *m.secret_key().to_bytes());

            for c in tv.chains.iter() {
                let ck = seed.derive::<secp256k1_ecdsa::SecretKey>(&c.chain);

                let mut expected_chain_code = [0u8; 32];
                hex::decode_to_slice(c.chain_code, &mut expected_chain_code as &mut [u8]).unwrap();
                assert_eq!(expected_chain_code, *ck.chain_code());

                let mut expected_private_key = [0u8; 32];
                hex::decode_to_slice(c.private_key, &mut expected_private_key as &mut [u8]).unwrap();
                assert_eq!(expected_private_key, *ck.secret_key().to_bytes());

                let last_segment_non_hardened = !c.chain.segments().last().map_or(true, Segment::is_hardened);
                if last_segment_non_hardened {
                    let esk = seed.to_master_key::<secp256k1_ecdsa::SecretKey>();
                    let (head, tail) = c.chain.segments().split_at(c.chain.len() - 1);
                    let chain = Chain::from_segments(head.iter().cloned());
                    let segment = tail[0];
                    let esk = esk.derive(&chain);
                    let epk = esk.to_extended_public_key();
                    assert_eq!(esk.chain_code(), epk.chain_code());
                    assert_eq!(esk.secret_key().public_key(), epk.public_key());

                    let esk = esk.child_key(&segment);
                    let epk = epk.child_key(&segment);
                    assert_eq!(expected_chain_code, *esk.chain_code());
                    assert_eq!(expected_private_key, *esk.secret_key().to_bytes());
                    assert_eq!(esk.chain_code(), epk.chain_code());
                    assert_eq!(esk.secret_key().public_key(), epk.public_key());
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_test_vectors() -> Result<()> {
        let tvs = include!("fixtures/slip10_ed25519.rs");
        run_ed25519_test_vectors(&tvs)
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn secp256k1_test_vectors() -> Result<()> {
        use crypto::keys::slip10::Segment;
        let tvs = include!("fixtures/slip10_secp256k1.rs");
        run_secp256k1_test_vectors(&tvs)
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn secp256k1_public_key_test() {
        use crypto::keys::slip10::Slip10;
        use crypto::signatures::secp256k1_ecdsa;

        let seed = Seed::from_bytes(&[1]);
        let esk = seed.to_master_key::<secp256k1_ecdsa::SecretKey>();
        let epk = esk.to_extended_public_key();
        let mut epk_bytes = *epk.extended_bytes();
        assert_eq!(2, epk_bytes[0]);
        epk_bytes[0] = 5;
        assert!(Slip10::<secp256k1_ecdsa::PublicKey>::try_from_extended_bytes(&epk_bytes).is_err());
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn secp256k1_chain_test() {
        use crypto::signatures::secp256k1_ecdsa;

        let _ = Seed::from_bytes(&[1])
            .derive::<secp256k1_ecdsa::SecretKey>(&Chain::from_segments([0, 1, 2]))
            .secret_key()
            .public_key()
            .to_bytes();
    }
}
