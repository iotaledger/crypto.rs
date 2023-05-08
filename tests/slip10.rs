// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "slip10")]
mod test {
    #![allow(clippy::identity_op)]

    use crypto::{
        keys::slip10::{Chain, Curve, Seed, Segment},
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

    fn run_test_vectors(curve: Curve, tvs: &[TestVector]) -> Result<()> {
        for tv in tvs {
            let seed = Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key(curve);
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, *m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, *m.secret_key().to_bytes());

            for c in tv.chains.iter() {
                let ck = seed.derive(curve, &c.chain)?;

                let mut expected_chain_code = [0u8; 32];
                hex::decode_to_slice(c.chain_code, &mut expected_chain_code as &mut [u8]).unwrap();
                assert_eq!(expected_chain_code, *ck.chain_code());

                let mut expected_private_key = [0u8; 32];
                hex::decode_to_slice(c.private_key, &mut expected_private_key as &mut [u8]).unwrap();
                assert_eq!(expected_private_key, *ck.secret_key().to_bytes());

                let last_segment_non_hardened = !c.chain.segments().last().map_or(true, Segment::is_hardened);
                if last_segment_non_hardened && curve.is_non_hardened_supported() {
                    let esk = seed.to_master_key(curve);
                    let (head, tail) = c.chain.segments().split_at(c.chain.len() - 1);
                    let chain = Chain::from_segments(head);
                    let segment = tail[0];
                    let esk = esk.derive(&chain).unwrap();
                    let epk = esk.try_into_extended_public_key().unwrap();
                    assert_eq!(esk.chain_code(), epk.chain_code());
                    assert_eq!(esk.secret_key().public_key(), epk.public_key());

                    let esk = esk.child_key(&segment).unwrap();
                    let epk = epk.child_key(&segment).unwrap();
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
    fn slip10_ed25519_test_vectors() -> Result<()> {
        let tvs = include!("fixtures/slip10_ed25519.rs");

        run_test_vectors(Curve::Ed25519, &tvs)
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn slip10_secp256k1_test_vectors() -> Result<()> {
        let tvs = include!("fixtures/slip10_secp256k1.rs");

        run_test_vectors(Curve::Secp256k1, &tvs)
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn slip10_secp256k1_public_key_test() {
        use crypto::keys::slip10::ExtendedPublicKey;
        let seed = Seed::from_bytes(&[1]);
        let esk = seed.to_master_key(Curve::Secp256k1);
        let epk = esk.try_into_extended_public_key().unwrap();
        let mut epk_bytes = *epk.extended_bytes();
        assert_eq!(2, epk_bytes[0]);
        epk_bytes[0] = 5;
        assert!(ExtendedPublicKey::try_from_extended_bytes(Curve::Secp256k1, &epk_bytes).is_err());
    }
}
