// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::keys::slip10::{self, Segment};

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::*;
    use crate::signatures::ed25519;

    impl slip10::ToChain<Bip44> for ed25519::SecretKey {
        type Chain = [slip10::Hardened; 5];
        fn to_chain(bip44_chain: &Bip44) -> [slip10::Hardened; 5] {
            [
                Bip44::PURPOSE.harden(),
                bip44_chain.coin_type.harden(),
                bip44_chain.account.harden(),
                bip44_chain.change.harden(),
                bip44_chain.address_index.harden(),
            ]
        }
    }
}

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::*;
    use crate::signatures::secp256k1_ecdsa;

    impl slip10::ToChain<Bip44> for secp256k1_ecdsa::SecretKey {
        type Chain = [u32; 5];
        fn to_chain(bip44_chain: &Bip44) -> [u32; 5] {
            [
                Bip44::PURPOSE.harden().into(),
                bip44_chain.coin_type.harden().into(),
                bip44_chain.account.harden().into(),
                bip44_chain.change,
                bip44_chain.address_index,
            ]
        }
    }
}

/// Type of BIP44 chains that apply hardening rules depending on the derived key type.
///
/// For Ed225519 secret keys the final chain is as follows (all segments are hardened):
/// m / purpose' / coin_type' / account' / change' / address_index'
///
/// For Secp256k1 ECDSA secret keys the final chain is as follows (the first three segments are hardened):
/// m / purpose' / coin_type' / account' / change / address_index
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bip44 {
    pub coin_type: u32,
    pub account: u32,
    pub change: u32,
    pub address_index: u32,
}

impl Bip44 {
    pub const PURPOSE: u32 = 44;

    pub fn new(coin_type: u32) -> Self {
        Self {
            coin_type,
            account: 0,
            change: 0,
            address_index: 0,
        }
    }

    pub fn with_coin_type(mut self, s: u32) -> Self {
        self.coin_type = s;
        self
    }

    pub fn with_account(mut self, s: u32) -> Self {
        self.account = s;
        self
    }

    pub fn with_change(mut self, s: u32) -> Self {
        self.change = s;
        self
    }

    pub fn with_address_index(mut self, s: u32) -> Self {
        self.address_index = s;
        self
    }

    pub fn to_chain<K: slip10::ToChain<Self>>(&self) -> <K as slip10::ToChain<Self>>::Chain {
        K::to_chain(self)
    }

    pub fn derive<K>(&self, mk: &slip10::Slip10<K>) -> slip10::Slip10<K>
    where
        K: slip10::Derivable
            + slip10::WithSegment<<<K as slip10::ToChain<Bip44>>::Chain as IntoIterator>::Item>
            + slip10::ToChain<Bip44>,
        <K as slip10::ToChain<Bip44>>::Chain: IntoIterator,
        <<K as slip10::ToChain<Bip44>>::Chain as IntoIterator>::Item: Segment,
    {
        mk.derive(self.to_chain::<K>().into_iter())
    }

    pub fn derive_from_seed<K, S>(&self, seed: &S) -> slip10::Slip10<K>
    where
        K: slip10::IsSecretKey
            + slip10::WithSegment<<<K as slip10::ToChain<Bip44>>::Chain as IntoIterator>::Item>
            + slip10::ToChain<Bip44>,
        <K as slip10::ToChain<Bip44>>::Chain: IntoIterator,
        <<K as slip10::ToChain<Bip44>>::Chain as IntoIterator>::Item: Segment,
        S: AsRef<[u8]>,
    {
        self.derive(&slip10::Slip10::from_seed(seed))
    }

    /// Derive a number of children keys with optimization as follows:
    ///
    /// mk = m / purpose* / coin_type* / account* / change*
    /// child_i = mk / (address_index + i)*
    /// return (child_0, .., child_{address_count - 1})
    ///
    /// Star (*) denotes hardening rule specific for key type `K`.
    ///
    /// Address space should not overflow, if `k` is the first index such that `address_index + k` overflows (31-bit),
    /// then only the first `k` children are returned.
    pub fn derive_address_range<K, S>(
        &self,
        m: &slip10::Slip10<K>,
        address_count: usize,
    ) -> impl ExactSizeIterator<Item = slip10::Slip10<K>>
    where
        K: slip10::Derivable + slip10::WithSegment<S> + slip10::ToChain<Bip44, Chain = [S; 5]>,
        S: Segment + TryFrom<u32>,
        <S as TryFrom<u32>>::Error: core::fmt::Debug,
    {
        let chain: [_; 5] = self.to_chain::<K>();

        // maximum number segments is 2^31, trim usize value to fit u32
        let address_count = core::cmp::min(1 << 31, address_count) as u32;

        // BIP44 conversion rules are strict, the last element is address_index
        let address_start = chain[4];
        let hardening_bit: u32 = address_start.into() & slip10::HARDEN_MASK;
        // strip hardening bit as it may interfere and overflow
        let unhardened_start: u32 = address_start.unharden().into();
        // this is guaranteed to not overflow and be <= 2^31
        let unhardened_end: u32 = core::cmp::min(1_u32 << 31, unhardened_start + address_count);

        // this is the final range guaranteed to not overflow address_index space
        let child_segments = (unhardened_start..unhardened_end).map(move |unhardened_address_index| -> S {
            let address_index = hardening_bit | unhardened_address_index;
            // SAFETY: address_index is guaranteed to have the correct hardening as the target type `S`, so unwrap()
            // can't fail
            address_index.try_into().unwrap()
        });

        let mk = if child_segments.len() > 0 {
            m.derive(chain[..4].iter().copied())
        } else {
            // no need to derive mk if there's no child_segments, just use empty/zero one
            slip10::Slip10::new()
        };
        mk.children(child_segments)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BadPurpose;

impl From<BadPurpose> for crate::Error {
    fn from(inner: BadPurpose) -> Self {
        crate::Error::Bip44Error(inner)
    }
}

impl TryFrom<[u32; 5]> for Bip44 {
    type Error = BadPurpose;
    fn try_from(segments: [u32; 5]) -> Result<Self, Self::Error> {
        if let [Bip44::PURPOSE, coin_type, account, change, address_index] = segments {
            Ok(Self {
                coin_type,
                account,
                change,
                address_index,
            })
        } else {
            Err(BadPurpose)
        }
    }
}

impl From<[u32; 4]> for Bip44 {
    fn from(segments: [u32; 4]) -> Self {
        let [coin_type, account, change, address_index] = segments;
        Self {
            coin_type,
            account,
            change,
            address_index,
        }
    }
}

impl From<&Bip44> for [u32; 5] {
    fn from(bip44_chain: &Bip44) -> [u32; 5] {
        [
            Bip44::PURPOSE,
            bip44_chain.coin_type,
            bip44_chain.account,
            bip44_chain.change,
            bip44_chain.address_index,
        ]
    }
}

impl IntoIterator for Bip44 {
    type Item = u32;
    type IntoIter = core::array::IntoIter<u32, 5>;
    fn into_iter(self) -> Self::IntoIter {
        <[u32; 5]>::from(&self).into_iter()
    }
}
