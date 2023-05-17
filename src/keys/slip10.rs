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
    pub struct True;
    pub struct False;
    pub trait AsBool {
        fn as_bool() -> bool;
    }
    impl AsBool for True {
        fn as_bool() -> bool {
            true
        }
    }
    impl AsBool for False {
        fn as_bool() -> bool {
            false
        }
    }

    pub trait Curve {
        const SEEDKEY: &'static [u8];
    }

    #[derive(Clone, Copy, Debug)]
    pub struct SecretKey<C>(core::marker::PhantomData<C>);
    #[derive(Clone, Copy, Debug)]
    pub struct PublicKey<C>(core::marker::PhantomData<C>);

    pub trait Derivable {
        type Curve: Curve;
        const IS_NON_HARDENED_SUPPORTED: bool;
        type Key;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool;
        fn into_key(key_bytes: &[u8; 33]) -> Self::Key;
        fn add_key(key_bytes: &mut [u8; 33], parent_key: &[u8; 33]) -> bool;
        fn calc_non_hardened_data(key_bytes: &[u8; 33]) -> [u8; 33];
    }
}

pub use hazmat::{Curve, Derivable, PublicKey, SecretKey};

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::hazmat::*;
    use crate::signatures::ed25519;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Ed25519;

    impl Curve for Ed25519 {
        const SEEDKEY: &'static [u8] = b"ed25519 seed";
    }

    impl Derivable for SecretKey<Ed25519> {
        type Curve = Ed25519;
        const IS_NON_HARDENED_SUPPORTED: bool = false;
        type Key = ed25519::SecretKey;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            key_bytes[0] == 0
        }
        fn into_key(key_bytes: &[u8; 33]) -> Self::Key {
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

    pub type ExtendedSecretKey = super::ExtendedSecretKey<Ed25519>;
}

#[cfg(feature = "ed25519")]
pub use self::ed25519::Ed25519;

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::hazmat::*;
    use crate::signatures::secp256k1_ecdsa;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Secp256k1;

    impl Curve for Secp256k1 {
        const SEEDKEY: &'static [u8] = b"Bitcoin seed";
    }

    impl Derivable for SecretKey<Secp256k1> {
        type Curve = Secp256k1;
        const IS_NON_HARDENED_SUPPORTED: bool = true;
        type Key = secp256k1_ecdsa::SecretKey;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            debug_assert_eq!(0, key_bytes[0]);
            let sk_bytes: &[u8; 32] = unsafe { &*(key_bytes[1..].as_ptr() as *const [u8; 32]) };
            k256::SecretKey::from_bytes(sk_bytes.into()).is_ok()
        }
        fn into_key(key_bytes: &[u8; 33]) -> Self::Key {
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

    pub type ExtendedSecretKey = super::ExtendedSecretKey<Secp256k1>;

    impl Derivable for PublicKey<Secp256k1> {
        type Curve = Secp256k1;
        const IS_NON_HARDENED_SUPPORTED: bool = true;
        type Key = secp256k1_ecdsa::PublicKey;
        fn is_key_valid(key_bytes: &[u8; 33]) -> bool {
            (key_bytes[0] == 2 || key_bytes[0] == 3) && k256::PublicKey::from_sec1_bytes(key_bytes).is_ok()
        }
        fn into_key(key_bytes: &[u8; 33]) -> Self::Key {
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

    pub type ExtendedPublicKey = super::ExtendedPublicKey<Secp256k1>;
}

#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1;

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

    pub fn to_master_key<C: hazmat::Curve>(&self) -> ExtendedSecretKey<C>
    where
        hazmat::SecretKey<C>: hazmat::Derivable,
    {
        ExtendedSecretKey::from_seed(self)
    }

    pub fn derive<C: hazmat::Curve>(&self, chain: &Chain) -> crate::Result<ExtendedSecretKey<C>>
    where
        hazmat::SecretKey<C>: hazmat::Derivable,
    {
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

pub type ExtendedSecretKey<C> = Extended<hazmat::SecretKey<C>>;
pub type ExtendedPublicKey<C> = Extended<hazmat::PublicKey<C>>;

impl<C: hazmat::Curve> ExtendedSecretKey<C>
where
    hazmat::SecretKey<C>: hazmat::Derivable,
{
    pub fn from_seed(seed: &Seed) -> Self {
        let mut key = Self {
            key: core::marker::PhantomData,
            ext: [0; 65],
        };
        HMAC_SHA512(&seed.0, C::SEEDKEY, key.ext_mut());
        while !key.is_secret_key_valid() {
            let mut tmp = [0_u8; 64];
            tmp.copy_from_slice(&key.ext[1..]);
            HMAC_SHA512(&tmp, C::SEEDKEY, key.ext_mut());
            tmp.zeroize();
        }
        key
    }

    pub fn secret_key(&self) -> <hazmat::SecretKey<C> as hazmat::Derivable>::Key {
        self.key()
    }
}

impl<C: hazmat::Curve> From<&Seed> for ExtendedSecretKey<C>
where
    hazmat::SecretKey<C>: hazmat::Derivable,
{
    fn from(seed: &Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl<C: hazmat::Curve> ExtendedSecretKey<C>
where
    hazmat::SecretKey<C>: hazmat::Derivable,
    hazmat::PublicKey<C>: hazmat::Derivable,
{
    pub fn into_extended_public_key(&self) -> ExtendedPublicKey<C> {
        ExtendedPublicKey::<C>::from_extended_secret_key(self)
    }
}

impl<C: hazmat::Curve> ExtendedPublicKey<C>
where
    hazmat::SecretKey<C>: hazmat::Derivable,
    hazmat::PublicKey<C>: hazmat::Derivable,
{
    pub fn from_extended_secret_key(esk: &ExtendedSecretKey<C>) -> Self {
        let mut k = Self {
            key: core::marker::PhantomData,
            ext: [0_u8; 65],
        };
        k.ext[..33].copy_from_slice(&<hazmat::SecretKey<C> as hazmat::Derivable>::calc_non_hardened_data(
            esk.key_bytes(),
        ));
        k.ext[33..].copy_from_slice(esk.chain_code());
        k
    }
}

impl<C: hazmat::Curve> From<&ExtendedSecretKey<C>> for ExtendedPublicKey<C>
where
    hazmat::SecretKey<C>: hazmat::Derivable,
    hazmat::PublicKey<C>: hazmat::Derivable,
{
    fn from(esk: &ExtendedSecretKey<C>) -> Self {
        Self::from_extended_secret_key(esk)
    }
}

impl<C: hazmat::Curve> ExtendedPublicKey<C>
where
    hazmat::PublicKey<C>: hazmat::Derivable,
{
    pub fn public_key(&self) -> <hazmat::PublicKey<C> as hazmat::Derivable>::Key {
        self.key()
    }
}

impl<K: hazmat::Derivable> Extended<K> {
    fn key(&self) -> K::Key {
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
        if K::IS_NON_HARDENED_SUPPORTED || chain.all_hardened() {
            let mut key: Self = self.clone();
            for segment in &chain.0 {
                key = key.derive_child_key(segment);
            }
            Ok(key)
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key index for Ed25519 master secret key",
            })
        }
    }

    pub fn child_key(&self, segment: &Segment) -> crate::Result<Self> {
        if K::IS_NON_HARDENED_SUPPORTED || segment.is_hardened() {
            Ok(self.derive_child_key(segment))
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key index for Ed25519 master secret key",
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

    fn is_secret_key_valid(&self) -> bool {
        K::is_key_valid(self.key_bytes())
    }

    fn calc_data(&self, hardened: bool) -> [u8; 33] {
        if hardened {
            *self.key_bytes()
        } else {
            debug_assert!(K::IS_NON_HARDENED_SUPPORTED);
            K::calc_non_hardened_data(self.key_bytes())
        }
    }

    fn derive_child_key(&self, segment: &Segment) -> Self {
        debug_assert!(K::IS_NON_HARDENED_SUPPORTED || segment.is_hardened());

        let mut data = [0u8; 33 + 4];
        data[..33].copy_from_slice(&self.calc_data(segment.is_hardened()));
        data[33..].copy_from_slice(&segment.bs()); // ser32(i)

        let mut key = Self {
            key: core::marker::PhantomData,
            ext: [0; 65],
        };
        HMAC_SHA512(&data, self.chain_code(), key.ext_mut());
        while !K::add_key(key.key_bytes_mut(), self.key_bytes()) {
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
pub struct Segment(u32);

impl Segment {
    pub fn from_u32(i: u32) -> Self {
        Self(i)
    }

    pub fn is_hardened(&self) -> bool {
        self.0 & Self::HARDEN_MASK != 0
    }

    pub fn bs(&self) -> [u8; 4] {
        self.0.to_be_bytes() // ser32(i)
    }

    pub const HARDEN_MASK: u32 = 1 << 31;
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
        Self(is.into_iter().map(Segment::from_u32).collect())
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
        self.0.iter().all(|s| !s.is_hardened())
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
