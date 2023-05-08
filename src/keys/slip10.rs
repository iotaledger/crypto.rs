// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]

use alloc::vec::Vec;
use core::convert::TryFrom;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::macs::hmac::HMAC_SHA512;
#[cfg(feature = "ed25519")]
use crate::signatures::ed25519;
#[cfg(feature = "secp256k1")]
use crate::signatures::secp256k1_ecdsa;

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Curve {
    #[cfg(feature = "ed25519")]
    Ed25519,
    #[cfg(feature = "secp256k1")]
    Secp256k1,
}

impl Curve {
    pub fn is_non_hardened_supported(&self) -> bool {
        match self {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => false,
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => true,
        }
    }

    fn seedkey(&self) -> &[u8] {
        match self {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => b"ed25519 seed",
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => b"Bitcoin seed",
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub enum SecretKey {
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::SecretKey),
    #[cfg(feature = "secp256k1")]
    Secp256k1Ecdsa(secp256k1_ecdsa::SecretKey),
}

impl SecretKey {
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(sk) => sk.to_bytes(),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1Ecdsa(sk) => sk.to_bytes(),
        }
    }
    pub fn public_key(&self) -> PublicKey {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(sk) => PublicKey::Ed25519(sk.public_key()),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1Ecdsa(sk) => PublicKey::Secp256k1Ecdsa(sk.public_key()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKey {
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::PublicKey),
    #[cfg(feature = "secp256k1")]
    Secp256k1Ecdsa(secp256k1_ecdsa::PublicKey),
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

    pub fn to_master_key(&self, curve: Curve) -> ExtendedSecretKey {
        ExtendedSecretKey::from_seed(curve, self)
    }

    pub fn derive(&self, curve: Curve, chain: &Chain) -> crate::Result<ExtendedSecretKey> {
        self.to_master_key(curve).derive(chain)
    }
}

pub type ChainCode = [u8; 32];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedSecretKey(KeyImpl);

impl ExtendedSecretKey {
    pub fn from_seed(curve: Curve, seed: &Seed) -> Self {
        Self(KeyImpl::from_seed(curve, &seed.0))
    }

    pub fn try_from_extended_bytes(curve: Curve, ext_bytes: &[u8; 64]) -> crate::Result<Self> {
        let mut key = KeyImpl { curve, ext: [0_u8; 65] };
        key.ext[1..].copy_from_slice(ext_bytes);
        if key.is_secret_key_valid() {
            Ok(Self(key))
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "extended secret key",
            })
        }
    }

    pub fn curve(&self) -> Curve {
        self.0.curve
    }

    pub fn extended_bytes(&self) -> &[u8; 64] {
        self.0.extended_secret_bytes()
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.0.secret_bytes()
    }

    pub fn secret_key(&self) -> SecretKey {
        match self.curve() {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => SecretKey::Ed25519(ed25519::SecretKey::from_bytes(self.secret_bytes())),
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => secp256k1_ecdsa::SecretKey::try_from_bytes(self.secret_bytes())
                .map(SecretKey::Secp256k1Ecdsa)
                .expect("valid extended secret key"),
        }
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        self.0.chain_code()
    }

    pub fn child_key(&self, segment: &Segment) -> crate::Result<Self> {
        #[cfg(feature = "ed25519")]
        if self.0.curve == Curve::Ed25519 && !segment.is_hardened() {
            return Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key index for Ed25519 master secret key",
            });
        }

        Ok(Self(self.0.child_key(segment)))
    }

    pub fn derive(&self, chain: &Chain) -> crate::Result<Self> {
        #[cfg(feature = "ed25519")]
        if self.0.curve == Curve::Ed25519 && !chain.all_hardened() {
            return Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key index for Ed25519 master secret key",
            });
        }

        let mut key = self.0.clone();
        for segment in &chain.0 {
            key = key.child_key(segment);
        }
        Ok(Self(key))
    }

    pub fn try_into_extended_public_key(&self) -> crate::Result<ExtendedPublicKey> {
        if self.curve().is_non_hardened_supported() {
            let mut k = KeyImpl {
                curve: self.curve(),
                ext: [0_u8; 65],
            };
            k.ext[..33].copy_from_slice(&self.0.calc_public_bytes());
            k.ext[33..].copy_from_slice(self.chain_code());
            Ok(ExtendedPublicKey(k))
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "curve supporting non-hardened key derivation",
            })
        }
    }
}

#[derive(Clone)]
pub struct ExtendedPublicKey(KeyImpl);

impl ExtendedPublicKey {
    pub fn try_from_extended_bytes(curve: Curve, ext_bytes: &[u8; 65]) -> crate::Result<Self> {
        if !curve.is_non_hardened_supported() {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "curve supporting non-hardened key derivation",
            })
        } else {
            let key = KeyImpl { curve, ext: *ext_bytes };
            if !key.is_public_key_valid() {
                Err(crate::Error::InvalidArgumentError {
                    alg: "SLIP10",
                    expected: "valid extended public key",
                })
            } else {
                Ok(Self(key))
            }
        }
    }

    pub fn curve(&self) -> Curve {
        self.0.curve
    }

    pub fn extended_bytes(&self) -> &[u8; 65] {
        self.0.extended_public_bytes()
    }

    pub fn public_bytes(&self) -> &[u8; 33] {
        self.0.public_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        match self.curve() {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => {
                unreachable!("SLIP10 does not support non-hardened key derivation from Ed25519 public keys")
            }
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => secp256k1_ecdsa::PublicKey::try_from_bytes(self.public_bytes())
                .map(PublicKey::Secp256k1Ecdsa)
                .expect("valid extended public key"),
        }
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        self.0.chain_code()
    }

    pub fn child_key(&self, segment: &Segment) -> crate::Result<Self> {
        #[cfg(feature = "ed25519")]
        debug_assert_ne!(Curve::Ed25519, self.curve());

        if !segment.is_hardened() {
            Ok(Self(self.0.child_key(segment)))
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "non hardened key index for master public key",
            })
        }
    }

    pub fn derive(&self, chain: &Chain) -> crate::Result<Self> {
        #[cfg(feature = "ed25519")]
        debug_assert_ne!(Curve::Ed25519, self.curve());

        if chain.all_non_hardened() {
            let mut key = self.0.clone();
            for segment in &chain.0 {
                key = key.child_key(segment);
            }
            Ok(Self(key))
        } else {
            Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "non hardened key index for master public key",
            })
        }
    }
}

impl TryFrom<&ExtendedSecretKey> for ExtendedPublicKey {
    type Error = crate::Error;
    fn try_from(esk: &ExtendedSecretKey) -> crate::Result<Self> {
        esk.try_into_extended_public_key()
    }
}

#[derive(Clone)]
struct KeyImpl {
    curve: Curve,
    // for secret key derivation: 0 + sk + chain code
    // for public key derivation: SEC1-pk + chain code
    // SEC1-pk = (if y-coord is even { 2 } else { 3 }) + x-coord
    ext: [u8; 65],
}

impl Zeroize for KeyImpl {
    fn zeroize(&mut self) {
        self.ext.zeroize();
    }
}
impl Drop for KeyImpl {
    fn drop(&mut self) {
        self.zeroize()
    }
}
impl ZeroizeOnDrop for KeyImpl {}

impl KeyImpl {
    fn ext_mut(&mut self) -> &mut [u8; 64] {
        unsafe { &mut *(self.ext[1..].as_mut_ptr() as *mut [u8; 64]) }
    }

    fn extended_secret_bytes(&self) -> &[u8; 64] {
        unsafe { &*(self.ext[1..].as_ptr() as *const [u8; 64]) }
    }

    fn extended_public_bytes(&self) -> &[u8; 65] {
        &self.ext
    }

    fn secret_bytes(&self) -> &[u8; 32] {
        unsafe { &*(self.ext[1..33].as_ptr() as *const [u8; 32]) }
    }

    fn public_bytes(&self) -> &[u8; 33] {
        unsafe { &*(self.ext[..33].as_ptr() as *const [u8; 33]) }
    }

    fn chain_code(&self) -> &[u8; 32] {
        unsafe { &*(self.ext[33..].as_ptr() as *const [u8; 32]) }
    }

    fn is_secret_bytes(&self) -> bool {
        debug_assert!(self.ext[0] < 4);
        self.ext[0] == 0
    }

    fn is_public_bytes(&self) -> bool {
        debug_assert!(self.ext[0] < 4);
        self.ext[0] != 0
    }

    fn is_secret_key_valid(&self) -> bool {
        match self.curve {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => true,
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => k256::SecretKey::from_bytes(self.secret_bytes().into()).is_ok(),
        }
    }

    fn is_public_key_valid(&self) -> bool {
        match self.curve {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => unreachable!("ed25519 curve is not supported for non-hardened public key derivation"),
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => {
                (self.ext[0] == 2 || self.ext[0] == 3) && k256::PublicKey::from_sec1_bytes(self.public_bytes()).is_ok()
            }
        }
    }

    fn calc_public_bytes(&self) -> [u8; 33] {
        match self.curve {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => unreachable!(),
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => {
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                let sk =
                    k256::SecretKey::from_bytes(self.secret_bytes().into()).expect("valid Secp256k1 parent secret key");
                let pk = sk.public_key();
                let mut pk_bytes = [0_u8; 33];
                pk_bytes.copy_from_slice(pk.to_encoded_point(true).as_bytes());
                pk_bytes
            }
        }
    }

    fn calc_data_bytes(&self, hardened: bool) -> [u8; 33] {
        if hardened || self.is_public_bytes() {
            *self.public_bytes()
        } else {
            self.calc_public_bytes()
        }
    }

    fn from_seed(curve: Curve, seed: &[u8]) -> Self {
        let mut key = Self { curve, ext: [0; 65] };
        HMAC_SHA512(seed, curve.seedkey(), key.ext_mut());
        while !key.is_secret_key_valid() {
            let mut tmp = [0_u8; 64];
            tmp.copy_from_slice(&key.ext[1..]);
            HMAC_SHA512(&tmp, curve.seedkey(), key.ext_mut());
            tmp.zeroize();
        }
        key
    }

    fn add(&mut self, parent_key: &[u8; 33]) -> bool {
        debug_assert!(self.is_secret_bytes());
        debug_assert!(parent_key[0] < 4);

        match self.curve {
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => {
                debug_assert_eq!(0, parent_key[0]);
                true
            }
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => {
                use k256::{
                    elliptic_curve::{group::prime::PrimeCurveAffine, sec1::ToEncodedPoint},
                    AffinePoint, ProjectivePoint,
                };

                if let Ok(sk_delta) = k256::SecretKey::from_bytes(self.secret_bytes().into()) {
                    if parent_key[0] == 0 {
                        use core::convert::TryInto;
                        let sk = k256::SecretKey::from_bytes((&parent_key[1..]).try_into().unwrap())
                            .expect("valid Secp256k1 parent secret key");

                        let scalar_delta = sk_delta.to_nonzero_scalar();
                        let mut scalar = *sk.to_nonzero_scalar().as_ref();
                        scalar += scalar_delta.as_ref();

                        if scalar.is_zero().into() {
                            false
                        } else {
                            self.ext[1..33].copy_from_slice(&scalar.to_bytes());
                            true
                        }
                    } else {
                        let pk_delta = sk_delta.public_key();
                        let pk_parent =
                            k256::PublicKey::from_sec1_bytes(parent_key).expect("valid Secp256k1 parent public key");

                        let mut point: ProjectivePoint = pk_parent.as_affine().into();
                        point += pk_delta.as_affine();
                        let point_sum: AffinePoint = point.into();

                        if point_sum.is_identity().into() {
                            false
                        } else {
                            self.ext[..33].copy_from_slice(point_sum.to_encoded_point(true).as_bytes());
                            true
                        }
                    }
                } else {
                    false
                }
            }
        }
    }

    fn child_key(&self, segment: &Segment) -> Self {
        let mut data = [0u8; 33 + 4];
        data[..33].copy_from_slice(&self.calc_data_bytes(segment.is_hardened()));
        data[33..].copy_from_slice(&segment.bs()); // ser32(i)

        let mut key = Self {
            curve: self.curve,
            ext: [0; 65],
        };
        HMAC_SHA512(&data, self.chain_code(), key.ext_mut());
        while !key.add(self.public_bytes()) {
            data[0] = 1;
            data[1..1 + 32].copy_from_slice(key.secret_bytes());
            HMAC_SHA512(&data, self.chain_code(), key.ext_mut());
        }

        data.zeroize();
        key
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
