// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://tools.ietf.org/html/rfc7748
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

// nomenclature compromise:
// RFC7748   Bernstein's 2006 paper
// scalar/u  secret/public
// X25519    Curve25519

use core::convert::TryInto;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;

/// An X25519 Shared Secret - the result of a Diffie-Hellman key exchange.
///
/// Each party computes this from an (ephemeral) [`SecretKey`] and their counterparty's [`PublicKey`].
pub type SharedSecret = x25519_dalek::SharedSecret;

/// An X25519 Public Key
pub struct PublicKey(x25519_dalek::PublicKey);

impl PublicKey {
    /// Load a [`PublicKey`] from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let array: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "X25519 Public Key",
        })?;

        Ok(Self(array.into()))
    }

    /// Returns the [`PublicKey`] as an array of bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Returns the [`PublicKey`] as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// An X25519 Secret Key
pub struct SecretKey(x25519_dalek::StaticSecret);

impl SecretKey {
    /// Generate a new random [`SecretKey`].
    #[cfg(feature = "random")]
    pub fn generate() -> crate::Result<Self> {
        let mut bytes: [u8; SECRET_KEY_LEN] = [0; SECRET_KEY_LEN];

        crate::rand::fill(&mut bytes[..])?;

        Self::from_bytes(&bytes[..])
    }

    /// Load a [`SecretKey`] from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let array: [u8; SECRET_KEY_LEN] = bytes.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "X25519 Secret Key",
        })?;

        Ok(Self(array.into()))
    }

    /// Returns the [`SecretKey`] as an array of bytes.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Returns the [`PublicKey`] which corresponds to this [`SecretKey`].
    pub fn public_key(&self) -> PublicKey {
        PublicKey((&self.0).into())
    }

    /// Computes the Diffie-Hellman [`SharedSecret`] from the [`SecretKey`] and the given [`PublicKey`].
    pub fn diffie_hellman(&self, public: &PublicKey) -> SharedSecret {
        self.0.diffie_hellman(&public.0)
    }
}
