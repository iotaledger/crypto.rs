// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]

use alloc::vec::Vec;
use core::convert::TryFrom;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::macs::hmac::HMAC_SHA512;

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

/// The traits in hazmat module are implementation internals.
/// The traits are made public due to other public API requiring them.
/// The traits are not exported to prevent third parties from implementing them outside this crate. This prevents third
/// parties from importing and using them in polymorphic contexts.
mod hazmat {
    use super::Segment;
    /// Derivable secret and public keys.
    pub trait Derivable {
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool;
        fn to_key(key_bytes: &[u8; 33]) -> Self;
        fn add_key(key_bytes: &mut [u8; 33], parent_key: &[u8; 33]) -> bool;
    }
    /// Derivable secret key.
    pub trait IsSecretKey: Derivable {
        const SEEDKEY: &'static [u8];
        /// Type of corresponding public key; PublicKey type may not be Derivable as is the case with ed25519.
        type PublicKey;
    }
    /// Derivable public key.
    pub trait IsPublicKey: Derivable {
        /// Corresponding derivable secret key type
        type SecretKey: IsSecretKey;
    }
    /// Derivable secret key whose corresponding public key is also derivable.
    // The trait should have been defined as `trait ToPublic: IsSecretKey where Self::PublicKey: IsPublicKey<SecretKey =
    // Self>`. It makes generic arguments more complex and seems like overkill.
    pub trait ToPublic: IsSecretKey {
        fn to_public(sk_bytes: &[u8; 33]) -> [u8; 33];
    }
    /// Keys that can be used to compute "data" argument of SLIP10 derivation algorithm for a specific segment type.
    pub trait CalcData<S: Segment> {
        fn calc_data(key_bytes: &[u8; 33], segment: S) -> [u8; 33];
    }
}

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::{hazmat::*, Hardened};
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

    impl CalcData<Hardened> for ed25519::SecretKey {
        fn calc_data(key_bytes: &[u8; 33], _segment: Hardened) -> [u8; 33] {
            *key_bytes
        }
    }
}

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::{hazmat::*, Hardened, NonHardened, Segment};
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

    impl IsSecretKey for secp256k1_ecdsa::SecretKey {
        const SEEDKEY: &'static [u8] = b"Bitcoin seed";
        type PublicKey = secp256k1_ecdsa::PublicKey;
    }

    impl ToPublic for secp256k1_ecdsa::SecretKey {
        fn to_public(key_bytes: &[u8; 33]) -> [u8; 33] {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            let sk = k256::SecretKey::from_bytes(sk_bytes.into()).expect("valid Secp256k1 parent secret key");
            let pk = sk.public_key();
            let mut pk_bytes = [0_u8; 33];
            pk_bytes.copy_from_slice(pk.to_encoded_point(true).as_bytes());
            pk_bytes
        }
    }

    impl CalcData<Hardened> for secp256k1_ecdsa::SecretKey {
        fn calc_data(key_bytes: &[u8; 33], _segment: Hardened) -> [u8; 33] {
            *key_bytes
        }
    }

    impl CalcData<NonHardened> for secp256k1_ecdsa::SecretKey {
        fn calc_data(key_bytes: &[u8; 33], _segment: NonHardened) -> [u8; 33] {
            Self::to_public(key_bytes)
        }
    }

    impl CalcData<u32> for secp256k1_ecdsa::SecretKey {
        fn calc_data(key_bytes: &[u8; 33], segment: u32) -> [u8; 33] {
            if segment.is_hardened() {
                Self::calc_data(key_bytes, Hardened(segment))
            } else {
                Self::calc_data(key_bytes, NonHardened(segment))
            }
        }
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

    impl IsPublicKey for secp256k1_ecdsa::PublicKey {
        type SecretKey = secp256k1_ecdsa::SecretKey;
    }

    impl CalcData<NonHardened> for secp256k1_ecdsa::PublicKey {
        fn calc_data(key_bytes: &[u8; 33], _segment: NonHardened) -> [u8; 33] {
            *key_bytes
        }
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

    pub fn to_master_key<K: hazmat::IsSecretKey>(&self) -> Slip10<K> {
        Slip10::from_seed(self)
    }

    pub fn derive<K, I>(&self, chain: I) -> Slip10<K>
    where
        K: hazmat::IsSecretKey + hazmat::CalcData<<I as Iterator>::Item>,
        I: Iterator,
        <I as Iterator>::Item: Segment,
    {
        self.to_master_key().derive(chain)
    }
}

#[cfg(feature = "bip39")]
impl From<super::bip39::Seed> for Seed {
    fn from(seed: super::bip39::Seed) -> Self {
        Self::from_bytes(seed.as_ref())
    }
}

/// Public bytestring that uniquely distinguishes different extended keys for the same key.
pub type ChainCode = [u8; 32];

/// Extended secret or public key, ie. a key extended with a chain code.
///
/// Extended keys must be handled with care. Security implications are explained in BIP32.
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

impl<K: hazmat::IsSecretKey> Slip10<K> {
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
        K::PublicKey: hazmat::IsPublicKey<SecretKey = K>,
        K: hazmat::ToPublic,
    {
        Slip10::from_extended_secret_key(self)
    }
}

impl<K: hazmat::IsSecretKey> From<&Seed> for Slip10<K> {
    fn from(seed: &Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl<K> Slip10<K>
where
    K: hazmat::IsPublicKey,
    K::SecretKey: hazmat::ToPublic,
{
    pub fn from_extended_secret_key(esk: &Slip10<K::SecretKey>) -> Self {
        let mut k = Self::new();
        k.ext[..33].copy_from_slice(&<K::SecretKey as hazmat::ToPublic>::to_public(esk.key_bytes()));
        k.ext[33..].copy_from_slice(esk.chain_code());
        k
    }
}

impl<K> From<&Slip10<K::SecretKey>> for Slip10<K>
where
    K: hazmat::IsPublicKey,
    K::SecretKey: hazmat::ToPublic,
{
    fn from(esk: &Slip10<K::SecretKey>) -> Self {
        Self::from_extended_secret_key(esk)
    }
}

impl<K: hazmat::IsPublicKey> Slip10<K> {
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

impl<K: hazmat::Derivable> Slip10<K> {
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

    pub fn derive<I>(&self, chain: I) -> Self
    where
        K: hazmat::IsSecretKey + hazmat::CalcData<<I as Iterator>::Item>,
        I: Iterator,
        <I as Iterator>::Item: Segment,
    {
        let mut key: Self = self.clone();
        for segment in chain {
            key = key.derive_child_key(segment);
        }
        key
    }

    pub fn child_key<S>(&self, segment: S) -> Self
    where
        S: Segment,
        K: hazmat::CalcData<S>,
    {
        self.derive_child_key(segment)
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

    fn calc_data<S>(&self, segment: S) -> [u8; 33]
    where
        S: Segment,
        K: hazmat::CalcData<S>,
    {
        K::calc_data(self.key_bytes(), segment)
    }

    fn derive_child_key<S>(&self, segment: S) -> Self
    where
        S: Segment,
        K: hazmat::CalcData<S>,
    {
        let mut data = [0u8; 33 + 4];
        data[..33].copy_from_slice(&self.calc_data(segment));
        data[33..].copy_from_slice(&segment.ser32());

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

impl<K: hazmat::Derivable> TryFrom<&[u8; 65]> for Slip10<K> {
    type Error = crate::Error;
    fn try_from(ext_bytes: &[u8; 65]) -> crate::Result<Self> {
        Self::try_from_extended_bytes(ext_bytes)
    }
}

/// Segment of a derivation chain.
pub trait Segment: Copy + Into<u32> {
    fn is_hardened(self) -> bool;
    fn ser32(self) -> [u8; 4] {
        self.into().to_be_bytes()
    }
    fn harden(self) -> Hardened;
    fn unharden(self) -> NonHardened;
}

/// Error indicating unexpected/invalid segment hardening.
/// Some keys only accept certain segments: either hardened or non-hardened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentHardeningError {
    /// Input segment is hardened, expected non-hardened segment only.
    Hardened,
    /// Input segment is non-hardened, expected hardened segment only.
    NonHardened,
}

impl From<SegmentHardeningError> for crate::Error {
    fn from(inner: SegmentHardeningError) -> Self {
        crate::Error::Slip10Error(inner)
    }
}

const HARDEN_MASK: u32 = 1 << 31;

/// `u32` type can represent both hardened and non-hardened segments.
impl Segment for u32 {
    fn is_hardened(self) -> bool {
        self & HARDEN_MASK != 0
    }
    fn harden(self) -> Hardened {
        Hardened(self | HARDEN_MASK)
    }
    fn unharden(self) -> NonHardened {
        NonHardened(self & !HARDEN_MASK)
    }
}

/// Type of hardened segments.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Hardened(u32);

impl From<Hardened> for u32 {
    fn from(segment: Hardened) -> u32 {
        segment.0
    }
}

impl TryFrom<u32> for Hardened {
    type Error = SegmentHardeningError;
    fn try_from(segment: u32) -> Result<Self, SegmentHardeningError> {
        if segment.is_hardened() {
            Ok(Hardened(segment))
        } else {
            Err(SegmentHardeningError::NonHardened)
        }
    }
}

impl Segment for Hardened {
    fn is_hardened(self) -> bool {
        true
    }
    fn harden(self) -> Hardened {
        self
    }
    fn unharden(self) -> NonHardened {
        NonHardened(self.0 ^ HARDEN_MASK)
    }
}

/// Type of non-hardened segments.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NonHardened(u32);

impl From<NonHardened> for u32 {
    fn from(segment: NonHardened) -> u32 {
        segment.0
    }
}

impl TryFrom<u32> for NonHardened {
    type Error = SegmentHardeningError;
    fn try_from(segment: u32) -> Result<Self, SegmentHardeningError> {
        if !segment.is_hardened() {
            Ok(NonHardened(segment))
        } else {
            Err(SegmentHardeningError::Hardened)
        }
    }
}

impl Segment for NonHardened {
    fn is_hardened(self) -> bool {
        false
    }
    fn harden(self) -> Hardened {
        Hardened(self.0 ^ HARDEN_MASK)
    }
    fn unharden(self) -> NonHardened {
        self
    }
}
