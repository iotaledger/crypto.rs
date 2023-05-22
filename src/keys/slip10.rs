// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]

use alloc::vec::Vec;
use core::convert::TryFrom;

// TODO: derive(Serialize, Deserialize) for Chain
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::macs::hmac::HMAC_SHA512;

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

pub mod hazmat {
    pub trait Derivable {
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool;
        fn into_key(key_bytes: &[u8; 33]) -> Self;
        fn add_key(key_bytes: &mut [u8; 33], parent_key: &[u8; 33]) -> bool;

        const ALLOW_NON_HARDENED: bool;
        fn calc_non_hardened_data(key_bytes: &[u8; 33]) -> [u8; 33];
    }
    pub trait IsSecretKey: Derivable {
        const SEEDKEY: &'static [u8];
        // PublicKey type may not be Derivable as is the case with ed25519
        type PublicKey;
    }
    pub trait IsPublicKey: Derivable {
        type SecretKey: IsSecretKey;
    }
}

pub use hazmat::{Derivable, IsPublicKey, IsSecretKey};

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::hazmat::*;
    use crate::signatures::ed25519;

    impl Derivable for ed25519::SecretKey {
        const ALLOW_NON_HARDENED: bool = false;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            key_bytes[0] == 0
        }
        fn into_key(key_bytes: &[u8; 33]) -> Self {
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            ed25519::SecretKey::from_bytes(sk_bytes)
        }
        fn add_key(_key_bytes: &mut [u8; 33], _parent_key: &[u8; 33]) -> bool {
            true
        }
        fn calc_non_hardened_data(_key_bytes: &[u8; 33]) -> [u8; 33] {
            unreachable!()
        }
    }

    impl IsSecretKey for ed25519::SecretKey {
        const SEEDKEY: &'static [u8] = b"ed25519 seed";
        type PublicKey = ed25519::PublicKey;
    }

    pub type ExtendedSecretKey = super::Extended<ed25519::SecretKey>;
}

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::hazmat::*;
    use crate::signatures::secp256k1_ecdsa;

    impl Derivable for secp256k1_ecdsa::SecretKey {
        const ALLOW_NON_HARDENED: bool = true;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            k256::SecretKey::from_bytes(sk_bytes.into()).is_ok()
        }
        fn into_key(key_bytes: &[u8; 33]) -> Self {
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
        fn calc_non_hardened_data(key_bytes: &[u8; 33]) -> [u8; 33] {
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

    impl IsSecretKey for secp256k1_ecdsa::SecretKey {
        const SEEDKEY: &'static [u8] = b"Bitcoin seed";
        type PublicKey = secp256k1_ecdsa::PublicKey;
    }

    impl Derivable for secp256k1_ecdsa::PublicKey {
        const ALLOW_NON_HARDENED: bool = true;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            (key_bytes[0] == 2 || key_bytes[0] == 3) && k256::PublicKey::from_sec1_bytes(key_bytes).is_ok()
        }
        fn into_key(key_bytes: &[u8; 33]) -> Self {
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
        fn calc_non_hardened_data(key_bytes: &[u8; 33]) -> [u8; 33] {
            *key_bytes
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

    pub fn to_master_key<K: hazmat::IsSecretKey>(&self) -> Extended<K> {
        Extended::from_seed(self)
    }

    pub fn derive<K: hazmat::IsSecretKey>(&self, chain: &Chain) -> crate::Result<Extended<K>> {
        self.to_master_key().derive(chain)
    }
}

pub type ChainCode = [u8; 32];

pub struct Extended<K> {
    key: core::marker::PhantomData<K>,
    ext: [u8; 65],
}

impl<K> Clone for Extended<K> {
    fn clone(&self) -> Self {
        Self {
            key: core::marker::PhantomData,
            ext: self.ext,
        }
    }
}

impl<K> Zeroize for Extended<K> {
    fn zeroize(&mut self) {
        self.ext.zeroize()
    }
}

impl<K> Drop for Extended<K> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<K> ZeroizeOnDrop for Extended<K> {}

impl<K: hazmat::IsSecretKey> Extended<K> {
    pub fn from_seed(seed: &Seed) -> Self {
        let mut key = Self {
            key: core::marker::PhantomData,
            ext: [0; 65],
        };
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

    pub fn into_extended_public_key(&self) -> Extended<K::PublicKey>
    where
        K::PublicKey: hazmat::IsPublicKey<SecretKey = K>,
    {
        Extended::from_extended_secret_key(self)
    }
}

impl<K: hazmat::IsSecretKey> From<&Seed> for Extended<K> {
    fn from(seed: &Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl<K: hazmat::IsPublicKey> Extended<K> {
    pub fn from_extended_secret_key(esk: &Extended<K::SecretKey>) -> Self {
        let mut k = Self {
            key: core::marker::PhantomData,
            ext: [0_u8; 65],
        };
        k.ext[..33].copy_from_slice(&<K::SecretKey as hazmat::Derivable>::calc_non_hardened_data(
            esk.key_bytes(),
        ));
        k.ext[33..].copy_from_slice(esk.chain_code());
        k
    }
}

impl<K: hazmat::IsPublicKey> From<&Extended<K::SecretKey>> for Extended<K> {
    fn from(esk: &Extended<K::SecretKey>) -> Self {
        Self::from_extended_secret_key(esk)
    }
}

impl<K: hazmat::IsPublicKey> Extended<K> {
    pub fn public_key(&self) -> K {
        self.key()
    }
}

impl<K: hazmat::Derivable> Extended<K> {
    fn key(&self) -> K {
        K::into_key(self.key_bytes())
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

    pub fn derive(&self, chain: &Chain) -> crate::Result<Self> {
        if K::ALLOW_NON_HARDENED || chain.all_hardened() {
            let mut key: Self = self.clone();
            for segment in &chain.0 {
                key = key.derive_child_key(segment);
            }
            Ok(key)
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key index",
            })
        }
    }

    pub fn child_key(&self, segment: &Segment) -> crate::Result<Self> {
        if K::ALLOW_NON_HARDENED || segment.is_hardened() {
            Ok(self.derive_child_key(segment))
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key index",
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

    fn calc_data(&self, hardened: bool) -> [u8; 33] {
        if hardened {
            *self.key_bytes()
        } else {
            debug_assert!(K::ALLOW_NON_HARDENED);
            K::calc_non_hardened_data(self.key_bytes())
        }
    }

    fn derive_child_key(&self, segment: &Segment) -> Self {
        debug_assert!(K::ALLOW_NON_HARDENED || segment.is_hardened());

        let mut data = [0u8; 33 + 4];
        data[..33].copy_from_slice(&self.calc_data(segment.is_hardened()));
        data[33..].copy_from_slice(&segment.bs()); // ser32(i)

        let mut key = Self {
            key: core::marker::PhantomData,
            ext: [0; 65],
        };
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

impl<K: hazmat::Derivable> TryFrom<&[u8; 65]> for Extended<K> {
    type Error = crate::Error;
    fn try_from(ext_bytes: &[u8; 65]) -> crate::Result<Self> {
        Self::try_from_extended_bytes(ext_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Segment(pub u32);

impl Segment {
    pub fn is_hardened(&self) -> bool {
        self.0 & Self::HARDEN_MASK != 0
    }

    pub fn is_non_hardened(&self) -> bool {
        !self.is_hardened()
    }

    pub fn bs(&self) -> [u8; 4] {
        self.0.to_be_bytes() // ser32(i)
    }

    pub const HARDEN_MASK: u32 = 1 << 31;
}

impl From<u32> for Segment {
    fn from(i: u32) -> Self {
        Self(i)
    }
}

impl From<Segment> for u32 {
    fn from(s: Segment) -> Self {
        s.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Chain(Vec<Segment>);

impl Chain {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_segments<'a, I: IntoIterator<Item = &'a Segment>>(is: I) -> Self {
        Self(is.into_iter().cloned().collect())
    }

    pub fn from_u32<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self(is.into_iter().map(Segment).collect())
    }

    pub fn from_u32_hardened<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self::from_u32(is.into_iter().map(|i| Segment::HARDEN_MASK | i))
    }

    pub fn join<O: AsRef<Chain>>(&self, o: O) -> Self {
        let mut ss = self.0.clone();
        ss.extend_from_slice(&o.as_ref().0);
        Self(ss)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn segments(&self) -> &[Segment] {
        &self.0
    }

    pub fn all_hardened(&self) -> bool {
        self.0.iter().all(Segment::is_hardened)
    }

    pub fn all_non_hardened(&self) -> bool {
        !self.0.iter().any(Segment::is_hardened)
    }
}

impl Default for Chain {
    fn default() -> Self {
        Chain::empty()
    }
}

impl AsRef<Chain> for Chain {
    fn as_ref(&self) -> &Self {
        self
    }
}
