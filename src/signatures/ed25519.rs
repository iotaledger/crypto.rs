// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    hash::{Hash, Hasher},
};

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

pub struct SecretKey(ed25519_zebra::SigningKey);

impl SecretKey {
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bs = [0u8; SECRET_KEY_LENGTH];
        crate::utils::rand::fill(&mut bs)?;
        Ok(Self::from_bytes(bs))
    }

    #[cfg(feature = "rand")]
    pub fn generate_with<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut bs = [0_u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut bs);
        Self::from_bytes(bs)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(ed25519_zebra::VerificationKey::from(&self.0))
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.into()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self(bytes.into())
    }

    pub fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        slice.try_into().map(Self).map_err(|_| crate::Error::ConvertError {
            from: "byte slice",
            to: "Ed25519 private key",
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<[u8; PUBLIC_KEY_LENGTH]> for SecretKey {
    fn from(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = crate::Error;
    fn try_from(slice: &[u8]) -> crate::Result<Self> {
        Self::try_from_slice(slice)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PublicKey(ed25519_zebra::VerificationKey);

impl PublicKey {
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
        self.0.verify(&sig.0, msg).is_ok()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.into()
    }

    pub fn try_from_bytes(bytes: [u8; PUBLIC_KEY_LENGTH]) -> crate::Result<Self> {
        bytes.try_into().map(Self).map_err(|_| crate::Error::ConvertError {
            from: "compressed byte array",
            to: "Ed25519 public key",
        })
    }

    pub fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        slice.try_into().map(Self).map_err(|_| crate::Error::ConvertError {
            from: "compressed byte slice",
            to: "Ed25519 public key",
        })
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl TryFrom<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    type Error = crate::Error;
    fn try_from(bytes: [u8; PUBLIC_KEY_LENGTH]) -> crate::Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = crate::Error;
    fn try_from(slice: &[u8]) -> crate::Result<Self> {
        Self::try_from_slice(slice)
    }
}

impl From<PublicKey> for [u8; PUBLIC_KEY_LENGTH] {
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
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.into()
    }

    pub fn from_bytes(bs: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(ed25519_zebra::Signature::from(bs))
    }
}
