// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    cmp::Ordering,
    convert::TryFrom,
    hash::{Hash, Hasher},
};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[deprecated = "Use associated const SecretKey::LENGTH"]
pub const SECRET_KEY_LENGTH: usize = 32;
#[deprecated = "Use associated const PublicKey::LENGTH"]
pub const PUBLIC_KEY_LENGTH: usize = 32;
#[deprecated = "Use associated const Signature::LENGTH"]
pub const SIGNATURE_LENGTH: usize = 64;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(ed25519_zebra::SigningKey);

impl SecretKey {
    pub const LENGTH: usize = 32;

    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bs = [0u8; SecretKey::LENGTH];
        crate::utils::rand::fill(&mut bs)?;
        let sk = Self::from_bytes(&bs);
        bs.zeroize();
        Ok(sk)
    }

    #[cfg(feature = "rand")]
    pub fn generate_with<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut bs = [0_u8; SecretKey::LENGTH];
        rng.fill_bytes(&mut bs);
        let sk = Self::from_bytes(&bs);
        bs.zeroize();
        sk
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(ed25519_zebra::VerificationKey::from(&self.0))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; SecretKey::LENGTH]> {
        Zeroizing::new(self.0.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn from_bytes(bytes: &[u8; SecretKey::LENGTH]) -> Self {
        Self((*bytes).into())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PublicKey(ed25519_zebra::VerificationKey);

impl PublicKey {
    pub const LENGTH: usize = 32;

    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
        self.0.verify(&sig.0, msg).is_ok()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn to_bytes(self) -> [u8; PublicKey::LENGTH] {
        self.0.into()
    }

    pub fn try_from_bytes(bytes: [u8; PublicKey::LENGTH]) -> crate::Result<Self> {
        ed25519_zebra::VerificationKey::try_from(bytes)
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "compressed bytes",
                to: "Ed25519 public key",
            })
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<[u8; PublicKey::LENGTH]> for PublicKey {
    type Error = crate::Error;
    fn try_from(bytes: [u8; PublicKey::LENGTH]) -> crate::Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

impl From<PublicKey> for [u8; PublicKey::LENGTH] {
    fn from(pk: PublicKey) -> Self {
        pk.to_bytes()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.as_slice()).hash(state);
    }
}

pub struct Signature(ed25519_zebra::Signature);

impl Signature {
    pub const LENGTH: usize = 64;

    pub fn to_bytes(&self) -> [u8; Signature::LENGTH] {
        self.0.into()
    }

    pub fn from_bytes(bs: [u8; Signature::LENGTH]) -> Self {
        Self(ed25519_zebra::Signature::from(bs))
    }
}
