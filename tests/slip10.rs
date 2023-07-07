// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "slip10")]
mod slip10 {
    #![allow(clippy::identity_op)]

    use crypto::{keys::slip10, Result};

    struct TestChain {
        chain: Vec<u32>,
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
            let seed = slip10::Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key::<ed25519::SecretKey>();
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, *m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, *m.secret_key().to_bytes());

            for c in tv.chains.iter() {
                let hardened_chain = c.chain.iter().cloned().map(|segment| segment.try_into().unwrap());
                let ck: slip10::Slip10<ed25519::SecretKey> = seed.derive(hardened_chain);

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
        use crypto::signatures::secp256k1_ecdsa;

        for tv in tvs {
            let seed = slip10::Seed::from_bytes(&hex::decode(tv.seed).unwrap());

            let m = seed.to_master_key::<secp256k1_ecdsa::SecretKey>();
            let mut expected_master_chain_code = [0u8; 32];
            hex::decode_to_slice(tv.master_chain_code, &mut expected_master_chain_code as &mut [u8]).unwrap();
            assert_eq!(expected_master_chain_code, *m.chain_code());

            let mut expected_master_private_key = [0u8; 32];
            hex::decode_to_slice(tv.master_private_key, &mut expected_master_private_key as &mut [u8]).unwrap();
            assert_eq!(expected_master_private_key, *m.secret_key().to_bytes());

            for c in tv.chains.iter() {
                let ck = seed.derive::<secp256k1_ecdsa::SecretKey, _>(c.chain.iter().cloned());

                let mut expected_chain_code = [0u8; 32];
                hex::decode_to_slice(c.chain_code, &mut expected_chain_code as &mut [u8]).unwrap();
                assert_eq!(expected_chain_code, *ck.chain_code());

                let mut expected_private_key = [0u8; 32];
                hex::decode_to_slice(c.private_key, &mut expected_private_key as &mut [u8]).unwrap();
                assert_eq!(expected_private_key, *ck.secret_key().to_bytes());

                let last_segment_non_hardened = !c
                    .chain
                    .iter()
                    .cloned()
                    .last()
                    .map_or(true, slip10::Segment::is_hardened);
                if last_segment_non_hardened {
                    let esk = seed.to_master_key::<secp256k1_ecdsa::SecretKey>();
                    let (head, tail) = c.chain.split_at(c.chain.len() - 1);
                    let chain = head;
                    let segment: slip10::NonHardened = tail[0].try_into().unwrap();
                    let esk = esk.derive(chain.iter().cloned());
                    let epk = esk.to_extended_public_key();
                    assert_eq!(esk.chain_code(), epk.chain_code());
                    assert_eq!(esk.secret_key().public_key(), epk.public_key());

                    let esk = esk.child_key(segment);
                    let epk = epk.child_key(segment);
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
        use crypto::keys::slip10::Segment;
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
    fn secp256k1_chain_test() {
        use crypto::signatures::secp256k1_ecdsa;

        let _ = slip10::Seed::from_bytes(&[1])
            .derive::<secp256k1_ecdsa::SecretKey, _>([0, 1, 2].into_iter())
            .derive([0, 0x80000001, 2].into_iter())
            .derive([0x80000000, 0x80000001, 0x80000002].into_iter())
            .secret_key()
            .public_key()
            .to_bytes();
    }

    #[test]
    #[allow(dead_code, unused_variables)]
    fn test_generic() {
        use crypto::keys::slip10;

        fn derive0<K: slip10::Derivable + slip10::WithSegment<slip10::Hardened>>(
            ext: &slip10::Slip10<K>,
        ) -> slip10::Slip10<K> {
            use slip10::Segment;
            ext.child_key(0.harden())
        }

        fn derive1<K: slip10::Derivable + slip10::WithSegment<slip10::NonHardened>>(
            ext: &slip10::Slip10<K>,
        ) -> slip10::Slip10<K> {
            use slip10::Segment;
            ext.child_key(0.unharden())
        }

        let seed = slip10::Seed::from_bytes(&[0]);

        #[cfg(feature = "ed25519")]
        {
            use crypto::signatures::ed25519;
            let ext_sk = slip10::Slip10::<ed25519::SecretKey>::from_seed(&seed);
            let _ = derive0(&ext_sk);
        }

        #[cfg(feature = "secp256k1")]
        {
            use crypto::signatures::secp256k1_ecdsa;
            let ext_sk = slip10::Slip10::<secp256k1_ecdsa::SecretKey>::from_seed(&seed);
            let ext_sk = derive0(&ext_sk);
            let _ = derive1(&ext_sk);
            let ext_pk = ext_sk.to_extended_public_key();
            let _ = derive1(&ext_pk);
        }
    }

    fn run_test_bip44_address_overflow<K, S>()
    where
        K: slip10::IsSecretKey + slip10::WithSegment<S> + slip10::ToChain<slip10::Bip44, Chain = [S; 5]>,
        S: slip10::Segment + TryFrom<u32>,
        <S as TryFrom<u32>>::Error: core::fmt::Debug,
    {
        for address_index in [0x7ffffffd_u32, 0xfffffffd_u32] {
            let m = slip10::Slip10::<K>::from_seed(&[0]);

            let address_counts = [0, 1, 2, 3, 4, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, usize::MAX];

            // derive all keys explicitly
            let eks: Vec<_> = (0..3)
                .map(|i| {
                    let chain = [0, 1, 2, 3, address_index + i];
                    let bip44 = slip10::Bip44::from(chain);
                    bip44.derive(&m)
                })
                .collect();

            for address_count in address_counts {
                let chain = [0, 1, 2, 3, address_index];
                let bip44 = slip10::Bip44::from(chain);
                // derive keys with optimization
                let dks = bip44.derive_address_range(&m, address_count);

                assert_eq!(core::cmp::min(3, address_count), dks.len());
                dks.zip(eks.iter())
                    .for_each(|(dk, ek)| assert_eq!(dk.extended_bytes(), ek.extended_bytes()));
            }
        }
    }

    #[test]
    fn test_bip44() {
        #[cfg(feature = "ed25519")]
        {
            use crypto::signatures::ed25519;
            run_test_bip44_address_overflow::<ed25519::SecretKey, _>();
        }
        #[cfg(feature = "secp256k1")]
        {
            use crypto::signatures::secp256k1_ecdsa;
            run_test_bip44_address_overflow::<secp256k1_ecdsa::SecretKey, _>();
        }
    }
}
