// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{cmp::Ordering, convert::TryFrom};

pub const SECRET_KEY_LENGTH: usize = 32;
pub const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

pub struct SecretKey(ed25519_zebra::SigningKey);

impl SecretKey {
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bs = [0u8; SECRET_KEY_LENGTH];
        crate::utils::rand::fill(&mut bs)?;
        Self::from_le_bytes(bs)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(ed25519_zebra::VerificationKey::from(&self.0))
    }

    pub fn to_le_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.into()
    }

    pub fn from_le_bytes(bs: [u8; SECRET_KEY_LENGTH]) -> crate::Result<Self> {
        Ok(SecretKey(ed25519_zebra::SigningKey::from(bs)))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey(ed25519_zebra::VerificationKey);

impl PublicKey {
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
        self.0.verify(&sig.0, msg).is_ok()
    }

    pub fn to_compressed_bytes(&self) -> [u8; COMPRESSED_PUBLIC_KEY_LENGTH] {
        self.0.into()
    }

    pub fn from_compressed_bytes(bs: [u8; COMPRESSED_PUBLIC_KEY_LENGTH]) -> crate::Result<Self> {
        ed25519_zebra::VerificationKey::try_from(bs)
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "compressed bytes",
                to: "Ed25519 public key",
            })
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
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
        self.as_ref().partial_cmp(&other.as_ref())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_ref().cmp(&other.as_ref())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature(ed25519_zebra::Signature);

impl Signature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.into()
    }

    pub fn from_bytes(bs: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(ed25519_zebra::Signature::from(bs))
    }
}
