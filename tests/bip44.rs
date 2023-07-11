// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "bip44")]
mod bip44 {
    use crypto::keys::{bip44, slip10};

    fn run_test_bip44_address_overflow<K, S>()
    where
        K: slip10::IsSecretKey + slip10::WithSegment<S> + slip10::ToChain<bip44::Bip44, Chain = [S; 5]>,
        S: slip10::Segment + TryFrom<u32>,
        <S as TryFrom<u32>>::Error: core::fmt::Debug,
    {
        for address_index in [0x7ffffffd_u32, 0xfffffffd_u32] {
            let m = slip10::Slip10::<K>::from_seed(&[0]);

            let address_counts = [0, 1, 2, 3, 4, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, usize::MAX];

            // derive all keys explicitly
            let eks: Vec<_> = (0..3)
                .map(|i| {
                    let chain = [1, 2, 3, address_index + i];
                    let bip44 = bip44::Bip44::from(chain);
                    let ek = bip44.derive(&m);
                    let ek_from_seed = bip44.derive_from_seed::<K, _>(&[0]);
                    assert_eq!(ek.extended_bytes(), ek_from_seed.extended_bytes());
                    ek
                })
                .collect();

            for address_count in address_counts {
                let chain = [1, 2, 3, address_index];
                let bip44 = bip44::Bip44::from(chain);
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

    #[test]
    fn test_bip44_convert() {
        let bip44 = bip44::Bip44::from([1, 2, 3, 4]);
        assert_eq!(<[u32; 5]>::from(&bip44), [44, 1, 2, 3, 4]);
        assert_eq!(bip44, bip44::Bip44::try_from([44, 1, 2, 3, 4]).unwrap());
        assert!(bip44::Bip44::try_from([43, 1, 2, 3, 4]).is_err());
        assert_eq!(bip44.into_iter().collect::<Vec<_>>(), vec![44, 1, 2, 3, 4]);
    }
}
