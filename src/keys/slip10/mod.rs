// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]

use crate::{
    macs::hmac::HMAC_SHA512,
    signatures::{ed25519, secp256k1},
};

use core::{convert::TryFrom, default::Default};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use alloc::vec::Vec;

pub mod interface;
use interface::PrivateKey;

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Curve {
    Ed25519,
    Secp256k1,
}

impl Curve {
    fn seedkey(&self) -> &[u8] {
        match self {
            Curve::Ed25519 => b"ed25519 seed",
            Curve::Secp256k1 => b"Bitcoin seed",
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
pub struct Seed(Vec<u8>);

impl Seed {
    pub fn from_bytes(bs: &[u8]) -> Self {
        Self(bs.to_vec())
    }

    pub fn to_master_key(&self, curve: Curve) -> Key {
        let mut i = [0; 64];
        HMAC_SHA512(&self.0, curve.seedkey(), &mut i);
        Key(i)
    }

    pub fn derive(&self, curve: Curve, chain: &Chain) -> crate::Result<Key> {
        let key = self.to_master_key(curve);

        match curve {
            Curve::Ed25519 => <Key as PrivateKey<ed25519::SecretKey>>::derive(&key, chain),
            Curve::Secp256k1 => <Key as PrivateKey<secp256k1::SecretKey>>::derive(&key, chain),
        }
    }
}

pub type ChainCode = [u8; 32];

#[derive(Clone, Copy, Debug, Zeroize)]
pub struct Key([u8; 64]);

impl Key {
    pub fn chain_code(&self) -> ChainCode {
        let mut ir = [0; 32];
        ir.copy_from_slice(&self.0[32..]);
        ir
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 64 {
            return Err(crate::Error::BufferSize {
                name: "key",
                has: bs.len(),
                needs: 64,
            });
        }

        let mut ds = [0; 64];
        ds.copy_from_slice(bs);
        Ok(Self(ds))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Segment {
    hardened: bool,
    bs: [u8; 4],
}

impl Segment {
    fn new(values: (u32, bool)) -> Segment {
        Self {
            hardened: values.1,
            bs: values.0.to_be_bytes(),
        }
    }

    pub fn from_u32(i: u32) -> Self {
        Self {
            hardened: i >= Self::HARDEN_MASK,
            bs: i.to_be_bytes(), // ser32(i)
        }
    }

    pub fn hardened(&self) -> bool {
        self.hardened
    }

    pub fn bs(&self) -> [u8; 4] {
        self.bs
    }

    pub const HARDEN_MASK: u32 = 1 << 31;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Chain(Vec<Segment>);

impl Chain {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_u32<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self(is.into_iter().map(Segment::from_u32).collect())
    }

    pub fn new<I: IntoIterator<Item = (u32, bool)>>(is: I) -> Self {
        Self(is.into_iter().map(Segment::new).collect())
    }

    pub fn from_u32_hardened<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self::from_u32(is.into_iter().map(|i| Segment::HARDEN_MASK | i))
    }

    pub fn from_u32_mixed<I: IntoIterator<Item = (u32, bool)>>(is: I) -> Self {
        Self::new(is.into_iter().map(|(i, b)| {
            if b {
                (Segment::HARDEN_MASK | i, true)
            } else {
                (i, false)
            }
        }))
    }

    pub fn join<O: AsRef<Chain>>(&self, o: O) -> Self {
        let mut ss = self.0.clone();
        ss.extend_from_slice(&o.as_ref().0);
        Self(ss)
    }

    pub fn segments(&self) -> Vec<Segment> {
        self.0.clone()
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

impl Into<Vec<u8>> for Key {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Into<super::bip44::Segment> for Segment {
    fn into(self) -> super::bip44::Segment {
        super::bip44::Segment {
            hardened: self.hardened,
            i: as_u32_be(&self.bs),
        }
    }
}

fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) + ((array[1] as u32) << 16) + ((array[2] as u32) << 8) + ((array[3] as u32) << 0)
}

impl PrivateKey<ed25519::SecretKey> for Key {
    type SecretKey = ed25519::SecretKey;

    fn secret_key(&self) -> crate::Result<ed25519::SecretKey> {
        let mut il = [0; 32];
        il.copy_from_slice(&self.0[..32]);
        Ok(ed25519::SecretKey::from_bytes(il))
    }

    fn child_key(&self, segment: Segment) -> crate::Result<Key> {
        if !segment.hardened {
            return Err(crate::Error::InvalidArgumentError {
                alg: "SLIP10",
                expected: "hardened key",
            });
        }

        let mut data = [0u8; 1 + 32 + 4];
        data[1..1 + 32].copy_from_slice(&self.0[..32]); // ser256(k_par) = ser256(parse256(il)) = il
        data[1 + 32..1 + 32 + 4].copy_from_slice(&segment.bs); // ser32(i)

        let mut i = [0; 64];
        HMAC_SHA512(&data, &self.0[32..], &mut i);

        Ok(Self(i))
    }

    fn derive(&self, chain: &Chain) -> crate::Result<Key> {
        let mut k = *self;
        for c in &chain.0 {
            k = <Self as PrivateKey<ed25519::SecretKey>>::child_key(&k, *c)?;
        }
        Ok(k)
    }
}

impl PrivateKey<secp256k1::SecretKey> for Key {
    type SecretKey = secp256k1::SecretKey;

    fn secret_key(&self) -> crate::Result<secp256k1::SecretKey> {
        let mut il = [0; 32];
        il.copy_from_slice(&self.0[..32]);
        secp256k1::SecretKey::from_bytes(&il)
    }

    fn child_key(&self, segment: Segment) -> crate::Result<Key> {
        let (sk, cc) = self.0.split_at(32);

        let epk = secp256k1::ExtendedPrivateKey {
            secret_key: secp256k1::SecretKey::from_slice(&sk).unwrap(),
            chain_code: cc.to_vec(),
        };

        let new_epk = epk.child_key(&(segment.into()))?;

        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&new_epk.secret_key().to_bytes());
        key[32..].copy_from_slice(new_epk.chain_code());

        Ok(Self(key))
    }

    fn derive(&self, chain: &Chain) -> crate::Result<Key> {
        let mut k = *self;
        for c in &chain.0 {
            k = <Self as PrivateKey<secp256k1::SecretKey>>::child_key(&k, *c)?;
        }
        Ok(k)
    }
}
