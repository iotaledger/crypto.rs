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

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.as_slice()).hash(state);
    }
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKeyBytes(ed25519_zebra::VerificationKeyBytes);

impl PublicKeyBytes {
    pub const LENGTH: usize = PublicKey::LENGTH;

    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> crate::Result<bool> {
        Ok(self.into_public_key()?.verify(sig, msg))
    }

    pub fn into_public_key(self) -> crate::Result<PublicKey> {
        Ok(PublicKey(self.0.try_into().map_err(|_| {
            crate::Error::ConvertError {
                from: "Ed25519 public key bytes",
                to: "Ed25519 public key",
            }
        })?))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn to_bytes(self) -> [u8; PublicKey::LENGTH] {
        self.0.into()
    }

    pub fn from_bytes(bytes: [u8; PublicKey::LENGTH]) -> Self {
        Self(ed25519_zebra::VerificationKeyBytes::from(bytes))
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = crate::Error;

    fn try_from(value: PublicKeyBytes) -> Result<Self, Self::Error> {
        value.into_public_key()
    }
}

impl AsRef<[u8]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; PublicKey::LENGTH]> for PublicKeyBytes {
    fn from(bytes: [u8; PublicKey::LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<PublicKeyBytes> for [u8; PublicKey::LENGTH] {
    fn from(pk: PublicKeyBytes) -> Self {
        pk.to_bytes()
    }
}

impl PartialEq for PublicKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PublicKeyBytes {}

impl PartialOrd for PublicKeyBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKeyBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for PublicKeyBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.as_slice()).hash(state);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        let r_cmp = self.0.r_bytes().cmp(other.0.r_bytes());
        let s_cmp = self.0.s_bytes().cmp(other.0.s_bytes());
        r_cmp.then(s_cmp)
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <[u8; 64]>::from(self.0).hash(state);
    }
}
