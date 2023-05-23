// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]

use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::Deref;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::macs::hmac::HMAC_SHA512;

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

pub trait Derivable {
    fn is_key_valid(key_bytes: &[u8; 33]) -> bool;
    fn to_key(key_bytes: &[u8; 33]) -> Self;
    fn add_key(key_bytes: &mut [u8; 33], parent_key: &[u8; 33]) -> bool;
}
pub trait CalcNonHardenedData {
    fn calc_non_hardened_data(&self) -> [u8; 33];
}
pub trait CalcData<C> {
    fn calc_data(&self, segment: u32) -> [u8; 33];
}
impl<K: Derivable> CalcData<Chain> for Slip10<K>
where
    Self: CalcNonHardenedData,
{
    fn calc_data(&self, segment: u32) -> [u8; 33] {
        if segment.is_hardened() {
            *self.key_bytes()
        } else {
            self.calc_non_hardened_data()
        }
    }
}
impl<K: IsSecretKey> CalcData<HardenedChain> for Slip10<K>
where
    Self: CalcData<Chain> + CalcNonHardenedData,
{
    fn calc_data(&self, _segment: u32) -> [u8; 33] {
        *self.key_bytes()
    }
}
pub trait IsSecretKey: Derivable {
    const SEEDKEY: &'static [u8];
    // PublicKey type may not be Derivable as is the case with ed25519
    type PublicKey;
}
pub trait IsPublicKey: Derivable {
    type SecretKey: IsSecretKey;
}

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::*;
    use crate::signatures::ed25519;

    impl Derivable for ed25519::SecretKey {
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            key_bytes[0] == 0
        }
        fn to_key(key_bytes: &[u8; 33]) -> Self {
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            ed25519::SecretKey::from_bytes(sk_bytes)
        }
        fn add_key(_key_bytes: &mut [u8; 33], _parent_key: &[u8; 33]) -> bool {
            true
        }
    }

    impl IsSecretKey for ed25519::SecretKey {
        const SEEDKEY: &'static [u8] = b"ed25519 seed";
        type PublicKey = ed25519::PublicKey;
    }

    impl CalcData<HardenedChain> for Slip10<ed25519::SecretKey> {
        fn calc_data(&self, _segment: u32) -> [u8; 33] {
            *self.key_bytes()
        }
    }

    pub type ExtendedSecretKey = super::Slip10<ed25519::SecretKey>;
}

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::*;
    use crate::signatures::secp256k1_ecdsa;

    impl Derivable for secp256k1_ecdsa::SecretKey {
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            k256::SecretKey::from_bytes(sk_bytes.into()).is_ok()
        }
        fn to_key(key_bytes: &[u8; 33]) -> Self {
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            secp256k1_ecdsa::SecretKey::try_from_bytes(sk_bytes).expect("valid extended secret key")
        }
        fn add_key(key_bytes: &mut [u8; 33], parent_key: &[u8; 33]) -> bool {
            debug_assert_eq!(0, parent_key[0]);
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };

            if let Ok(sk_delta) = k256::SecretKey::from_bytes(sk_bytes.into()) {
                let sk = k256::SecretKey::from_bytes((&parent_key[1..]).try_into().unwrap())
                    .expect("valid Secp256k1 parent secret key");

                let scalar_delta = sk_delta.to_nonzero_scalar();
                let mut scalar = *sk.to_nonzero_scalar().as_ref();
                scalar += scalar_delta.as_ref();

                if scalar.is_zero().into() {
                    false
                } else {
                    key_bytes[1..].copy_from_slice(&scalar.to_bytes());
                    true
                }
            } else {
                false
            }
        }
    }

    impl CalcNonHardenedData for Slip10<secp256k1_ecdsa::SecretKey> {
        fn calc_non_hardened_data(&self) -> [u8; 33] {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let key_bytes = self.key_bytes();
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            let sk = k256::SecretKey::from_bytes(sk_bytes.into()).expect("valid Secp256k1 parent secret key");
            let pk = sk.public_key();
            let mut pk_bytes = [0_u8; 33];
            pk_bytes.copy_from_slice(pk.to_encoded_point(true).as_bytes());
            pk_bytes
        }
    }

    impl IsSecretKey for secp256k1_ecdsa::SecretKey {
        const SEEDKEY: &'static [u8] = b"Bitcoin seed";
        type PublicKey = secp256k1_ecdsa::PublicKey;
    }

    impl Derivable for secp256k1_ecdsa::PublicKey {
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            (key_bytes[0] == 2 || key_bytes[0] == 3) && k256::PublicKey::from_sec1_bytes(key_bytes).is_ok()
        }
        fn to_key(key_bytes: &[u8; 33]) -> Self {
            secp256k1_ecdsa::PublicKey::try_from_bytes(key_bytes)
                // implementation guarantees that it always succeeds
                .expect("valid extended public key")
        }
        fn add_key(key_bytes: &mut [u8; 33], parent_key: &[u8; 33]) -> bool {
            use k256::{
                elliptic_curve::{group::prime::PrimeCurveAffine, sec1::ToEncodedPoint},
                AffinePoint, ProjectivePoint,
            };
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };

            if let Ok(sk_delta) = k256::SecretKey::from_bytes(sk_bytes.into()) {
                let pk_delta = sk_delta.public_key();
                let pk_parent =
                    k256::PublicKey::from_sec1_bytes(parent_key).expect("valid Secp256k1 parent public key");

                let mut point: ProjectivePoint = pk_parent.as_affine().into();
                point += pk_delta.as_affine();
                let point_sum: AffinePoint = point.into();

                if point_sum.is_identity().into() {
                    false
                } else {
                    key_bytes.copy_from_slice(point_sum.to_encoded_point(true).as_bytes());
                    true
                }
            } else {
                false
            }
        }
    }

    impl CalcNonHardenedData for Slip10<secp256k1_ecdsa::PublicKey> {
        fn calc_non_hardened_data(&self) -> [u8; 33] {
            *self.key_bytes()
        }
    }

    impl IsPublicKey for secp256k1_ecdsa::PublicKey {
        type SecretKey = secp256k1_ecdsa::SecretKey;
    }
}

/// A seed is an arbitrary bytestring used to create the root of the tree.
///
/// Several standards generate and/or restricts the size of the seed:
/// BIP39: 512 bit seeds
/// BIP32: between 128 and 512 bits; 256 bits is advised
/// SLIP10: follows BIP32
///
/// But since the seed entropy is always passed through HMAC-SHA512 any bytesequence is acceptable,
/// therefore formally the size requirement is context sensitive.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed(Vec<u8>);

impl Seed {
    pub fn from_bytes(bs: &[u8]) -> Self {
        Self(bs.to_vec())
    }

    pub fn to_master_key<K: IsSecretKey>(&self) -> Slip10<K> {
        Slip10::from_seed(self)
    }

    pub fn derive<K: IsSecretKey, C: AsRef<Chain>>(&self, chain: &C) -> Slip10<K>
    where
        Slip10<K>: CalcData<C>,
    {
        self.to_master_key().derive(chain)
    }
}

pub type ChainCode = [u8; 32];

#[derive(ZeroizeOnDrop)]
pub struct Slip10<K> {
    key: core::marker::PhantomData<K>,
    ext: [u8; 65],
}

impl<K> Clone for Slip10<K> {
    fn clone(&self) -> Self {
        Self {
            key: core::marker::PhantomData,
            ext: self.ext,
        }
    }
}

impl<K> Zeroize for Slip10<K> {
    fn zeroize(&mut self) {
        self.ext.zeroize()
    }
}

impl<K: IsSecretKey> Slip10<K> {
    pub fn from_seed(seed: &Seed) -> Self {
        let mut key = Self::new();
        HMAC_SHA512(&seed.0, K::SEEDKEY, key.ext_mut());
        while !key.is_key_valid() {
            let mut tmp = [0_u8; 64];
            tmp.copy_from_slice(&key.ext[1..]);
            HMAC_SHA512(&tmp, K::SEEDKEY, key.ext_mut());
            tmp.zeroize();
        }
        key
    }

    pub fn secret_key(&self) -> K {
        self.key()
    }

    pub fn to_extended_public_key(&self) -> Slip10<K::PublicKey>
    where
        K::PublicKey: IsPublicKey<SecretKey = K>,
        Self: CalcNonHardenedData,
    {
        Slip10::from_extended_secret_key(self)
    }
}

impl<K: IsPublicKey> Slip10<K>
where
    Slip10<K::SecretKey>: CalcNonHardenedData,
{
    pub fn from_extended_secret_key(esk: &Slip10<K::SecretKey>) -> Self {
        let mut k = Self::new();
        k.ext[..33].copy_from_slice(&esk.calc_non_hardened_data());
        k.ext[33..].copy_from_slice(esk.chain_code());
        k
    }
}

impl<K: IsPublicKey> From<&Slip10<K::SecretKey>> for Slip10<K>
where
    Slip10<K::SecretKey>: CalcNonHardenedData,
{
    fn from(esk: &Slip10<K::SecretKey>) -> Self {
        Self::from_extended_secret_key(esk)
    }
}

impl<K: IsPublicKey> Slip10<K> {
    pub fn public_key(&self) -> K {
        self.key()
    }
}

impl<K> Slip10<K> {
    fn new() -> Self {
        Self {
            key: core::marker::PhantomData,
            ext: [0_u8; 65],
        }
    }
}

impl<K: Derivable> Slip10<K> {
    fn key(&self) -> K {
        K::to_key(self.key_bytes())
    }

    pub fn extended_bytes(&self) -> &[u8; 65] {
        &self.ext
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        unsafe { &*(self.ext[33..].as_ptr() as *const [u8; 32]) }
    }

    pub fn try_from_extended_bytes(ext_bytes: &[u8; 65]) -> crate::Result<Self> {
        let key_bytes: &[u8; 33] = unsafe { &*(ext_bytes[..33].as_ptr() as *const [u8; 33]) };
        if K::is_key_valid(key_bytes) {
            Ok(Self {
                key: core::marker::PhantomData,
                ext: *ext_bytes,
            })
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "valid extended key bytes",
            })
        }
    }

    fn ext_mut(&mut self) -> &mut [u8; 64] {
        unsafe { &mut *(self.ext[1..].as_mut_ptr() as *mut [u8; 64]) }
    }

    fn key_bytes(&self) -> &[u8; 33] {
        unsafe { &*(self.ext[..33].as_ptr() as *const [u8; 33]) }
    }

    fn key_bytes_mut(&mut self) -> &mut [u8; 33] {
        unsafe { &mut *(self.ext[..33].as_mut_ptr() as *mut [u8; 33]) }
    }

    fn add_key(&mut self, parent_key: &[u8; 33]) -> bool {
        K::add_key(self.key_bytes_mut(), parent_key)
    }

    fn is_key_valid(&self) -> bool {
        K::is_key_valid(self.key_bytes())
    }
}

impl<K: Derivable> Slip10<K> {
    pub fn derive<C: AsRef<Chain>>(&self, chain: &C) -> Self
    where
        Self: CalcData<C>,
    {
        let mut key: Self = self.clone();
        for &segment in &chain.as_ref().0 {
            key = key.derive_child_key(segment);
        }
        key
    }

    pub fn child_key<C>(&self, segment: u32) -> Self
    where
        Self: CalcData<C>,
    {
        self.derive_child_key(segment)
    }

    fn derive_child_key<C>(&self, segment: u32) -> Self
    where
        Self: CalcData<C>,
    {
        let mut data = [0u8; 33 + 4];
        data[..33].copy_from_slice(&self.calc_data(segment));
        data[33..].copy_from_slice(&segment.to_le_bytes()); // ser32(i)

        let mut key = Self::new();
        HMAC_SHA512(&data, self.chain_code(), key.ext_mut());
        while !key.add_key(self.key_bytes()) {
            data[0] = 1;
            data[1..1 + 32].copy_from_slice(key.key_bytes());
            HMAC_SHA512(&data, self.chain_code(), key.ext_mut());
        }

        data.zeroize();
        key
    }
}

impl<K: Derivable> TryFrom<&[u8; 65]> for Slip10<K> {
    type Error = crate::Error;
    fn try_from(ext_bytes: &[u8; 65]) -> crate::Result<Self> {
        Self::try_from_extended_bytes(ext_bytes)
    }
}

pub trait Segment {
    type Mask;
    const HARDEN_MASK: Self::Mask;

    fn is_hardened(&self) -> bool;
    fn to_hardened(self) -> Self;
}

impl Segment for u32 {
    type Mask = Self;
    const HARDEN_MASK: Self::Mask = 1 << 31;

    fn is_hardened(&self) -> bool {
        self & Self::HARDEN_MASK != 0
    }
    fn to_hardened(self) -> Self {
        Self::HARDEN_MASK | self
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Chain(Vec<u32>);

impl Chain {
    pub fn from_segments<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self(is.into_iter().collect())
    }

    pub fn from_segments_hardened<I: IntoIterator<Item = u32>>(is: I) -> HardenedChain {
        HardenedChain(Self(is.into_iter().map(u32::to_hardened).collect()))
    }

    pub fn join<O: Deref<Target = Chain>>(&self, o: O) -> Self {
        let mut ss = self.0.clone();
        ss.extend_from_slice(&o.0);
        Self(ss)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn segments(&self) -> &[u32] {
        &self.0
    }
}

impl AsRef<Chain> for Chain {
    fn as_ref(&self) -> &Chain {
        &self
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct HardenedChain(Chain);

impl Deref for HardenedChain {
    type Target = Chain;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Chain> for HardenedChain {
    fn as_ref(&self) -> &Chain {
        &self.0
    }
}
