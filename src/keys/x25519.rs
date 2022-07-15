// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://tools.ietf.org/html/rfc7748
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

// nomenclature compromise:
// RFC7748   Bernstein's 2006 paper
// scalar/u  secret/public
// X25519    Curve25519

#[cfg(feature = "ed25519")]
use core::convert::TryFrom;
use core::convert::TryInto;

#[cfg(feature = "ed25519")]
use crate::signatures::ed25519;

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SECRET_KEY_LENGTH: usize = 32;

/// An X25519 Shared Secret - the result of a Diffie-Hellman key exchange.
///
/// Each party computes this from an (ephemeral) [`SecretKey`] and their counterparty's [`PublicKey`].
pub type SharedSecret = x25519_dalek::SharedSecret;

/// An X25519 Public Key
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes.into())
    }

    /// Load a [`PublicKey`] from a slice of bytes.
    pub fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; PUBLIC_KEY_LENGTH] = slice.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "X25519 Public Key",
        })?;

        Ok(Self::from_bytes(bytes))
    }

    /// Returns the [`PublicKey`] as an array of bytes.
    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Returns the [`PublicKey`] as a slice of bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(feature = "ed25519")]
impl TryFrom<&ed25519::PublicKey> for PublicKey {
    type Error = crate::Error;
    fn try_from(pk: &ed25519::PublicKey) -> crate::Result<Self> {
        // We need to get `EdwardsPoint` from `pk`.
        // `pk.as_slice()` returns compressed Edwards Y coordinate bytes.
        let mut y_bytes = [0_u8; 32];
        y_bytes.copy_from_slice(pk.as_slice());
        // Try reconstruct X,Y,Z,T coordinates of `EdwardsPoint` from it.
        match curve25519_dalek::edwards::CompressedEdwardsY(y_bytes).decompress() {
            Some(decompressed_edwards) => {
                // `pk` is a valid `ed25519::PublicKey` hence contains valid `EdwardsPoint`.
                // x25519 uses Montgomery form, and `x25519::PublicKey` is just a `MontgomeryPoint`.
                // `MontgomeryPoint` can be constructed from `EdwardsPoint` with `to_montgomery()` method.
                // Can't construct `x25519::PublicKey` directly from `MontgomeryPoint`,
                // do it via intermediate bytes.
                Ok(PublicKey::from_bytes(decompressed_edwards.to_montgomery().to_bytes()))
            }
            None => Err(crate::error::Error::ConvertError {
                from: "ed25519 public key",
                to: "x25519 public key",
            }),
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<PublicKey> for [u8; PUBLIC_KEY_LENGTH] {
    fn from(pk: PublicKey) -> Self {
        pk.to_bytes()
    }
}

/// An X25519 Secret Key
pub struct SecretKey(x25519_dalek::StaticSecret);

impl SecretKey {
    /// Generate a new random [`SecretKey`].
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        crate::utils::rand::fill(&mut bytes[..])?;
        Ok(Self::from_bytes(bytes))
    }

    #[cfg(feature = "rand")]
    pub fn generate_with<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut bs = [0_u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut bs);
        Self::from_bytes(bs)
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self(bytes.into())
    }

    /// Load a [`SecretKey`] from a slice of bytes.
    pub fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; SECRET_KEY_LENGTH] = slice.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "X25519 Secret Key",
        })?;

        Ok(Self::from_bytes(bytes))
    }

    /// Returns the [`SecretKey`] as an array of bytes.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
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

#[cfg(all(feature = "ed25519", feature = "sha"))]
impl From<&ed25519::SecretKey> for SecretKey {
    fn from(sk: &ed25519::SecretKey) -> SecretKey {
        // We need to extract scalar from `sk`.
        // It's not directly accessible from `sk`,
        // nor can `x25519::SecretKey` be constructed directly with a scalar.
        // `ed25519::SecretKey` only exposes seed bytes,
        // we have to reconstruct scalar bytes from seed.
        use crate::hashes::Digest;
        let h = crate::hashes::sha::Sha512::digest(sk.as_slice());
        // The low half of hash is used as scalar bytes.
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[..].copy_from_slice(&h.as_slice()[0..32]);
        // No need to do "clamping" here, it's done in `x25519::SecretKey::from_bytes()` constructor.
        SecretKey::from_bytes(scalar_bytes)
    }
}
