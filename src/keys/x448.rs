// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://tools.ietf.org/html/rfc7748

use core::convert::TryInto;

pub const PUBLIC_KEY_LEN: usize = 56;
pub const SECRET_KEY_LEN: usize = 56;

/// An X448 Shared Secret - the result of a Diffie-Hellman key exchange.
///
/// Each party computes this from an (ephemeral) [`SecretKey`] and their counterparty's [`PublicKey`].
pub type SharedSecret = x448_crate::SharedSecret;

/// An X448 Public Key
pub struct PublicKey(x448_crate::PublicKey);

impl PublicKey {
    /// Load a [`PublicKey`] from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        x448_crate::PublicKey::from_bytes(bytes)
            .map(Self)
            .ok_or(crate::Error::ConvertError {
                from: "bytes",
                to: "X448 Public Key",
            })
    }

    /// Returns the [`PublicKey`] as an array of bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.0.as_bytes()
    }

    /// Returns the [`PublicKey`] as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// An X448 Secret Key
pub struct SecretKey(x448_crate::Secret);

impl SecretKey {
    /// Generate a new random [`SecretKey`].
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bytes: [u8; SECRET_KEY_LEN] = [0; SECRET_KEY_LEN];

        crate::utils::rand::fill(&mut bytes[..])?;

        Self::from_bytes(&bytes[..])
    }

    /// Load a [`SecretKey`] from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let array: [u8; SECRET_KEY_LEN] = bytes.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "X448 Secret Key",
        })?;

        Ok(Self(array.into()))
    }

    /// Returns the [`SecretKey`] as an array of bytes.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        *self.0.as_bytes()
    }

    /// Returns the [`PublicKey`] which corresponds to this [`SecretKey`].
    pub fn public_key(&self) -> PublicKey {
        PublicKey((&self.0).into())
    }

    /// Computes the Diffie-Hellman [`SharedSecret`] from the [`SecretKey`] and the given [`PublicKey`].
    pub fn diffie_hellman(&self, public: &PublicKey) -> SharedSecret {
        // unwrap is safe because low order points are checked with `PublicKey::from_bytes`.
        self.0.as_diffie_hellman(&public.0).unwrap()
    }
}
