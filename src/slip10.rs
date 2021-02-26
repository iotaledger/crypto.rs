// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use crate::{ed25519::SecretKey, macs::hmac::HMAC_SHA512};

use core::{convert::TryFrom, default::Default};

use alloc::vec::Vec;

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// https://en.bitcoin.it/wiki/BIP_0039

#[derive(Clone, Copy, Debug)]
pub enum Curve {
    Ed25519,
}

impl Curve {
    fn seedkey(&self) -> &[u8] {
        match self {
            Curve::Ed25519 => b"ed25519 seed",
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
        self.to_master_key(curve).derive(chain)
    }
}

pub type ChainCode = [u8; 32];

#[derive(Copy, Clone, Debug)]
pub struct Key([u8; 64]);

impl Key {
    pub fn secret_key(&self) -> crate::Result<SecretKey> {
        let mut il = [0; 32];
        il.copy_from_slice(&self.0[..32]);
        // TODO: this conversion should never fail
        SecretKey::from_le_bytes(il)
    }

    pub fn chain_code(&self) -> ChainCode {
        let mut ir = [0; 32];
        ir.copy_from_slice(&self.0[32..]);
        ir
    }

    pub fn child_key(&self, segment: &Segment) -> crate::Result<Key> {
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

    pub fn derive(&self, chain: &Chain) -> crate::Result<Key> {
        let mut k = *self;
        for c in &chain.0 {
            k = k.child_key(c)?;
        }
        Ok(k)
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 64 {
            return Err(crate::Error::BufferSize {
                has: bs.len(),
                needs: 64,
            });
        }

        let mut ds = [0; 64];
        ds.copy_from_slice(bs);
        Ok(Self(ds))
    }
}

#[derive(Debug, Clone)]
pub struct Segment {
    hardened: bool,
    bs: [u8; 4],
}

impl Segment {
    pub fn from_u32(i: u32) -> Self {
        Self {
            hardened: i >= Self::HARDEN_MASK,
            bs: i.to_be_bytes(), // ser32(i)
        }
    }

    pub const HARDEN_MASK: u32 = 1 << 31;
}

#[derive(Debug, Clone)]
pub struct Chain(Vec<Segment>);

impl Chain {
    pub fn empty() -> Self {
        Self(Vec::new())
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
}

impl Default for Chain {
    fn default() -> Self {
        Chain::empty()
    }
}

impl AsRef<Chain> for Chain {
    fn as_ref(&self) -> &Self {
        &self
    }
}

impl Into<Vec<u8>> for Key {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}
