// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryInto;
use k256::{
    elliptic_curve::{
        ecdh,
        generic_array::{typenum::Unsigned, GenericArray},
        sec1::{Coordinates, EncodedPoint, ToEncodedPoint, UntaggedPointSize},
    },
    Secp256k1,
};
use signature::{Error as SigError, Signer, Verifier};

/// A byte representation of an Secp256k1 field element.
pub type FieldBytes = k256::FieldBytes;

/// Secp256k1 Shared Secret - the result of a Diffie-Hellman key exchange.
///
/// Each party computes this from an (ephemeral) [SecretKey] and their counterparty's [PublicKey].
pub type SharedSecret = k256::ecdh::SharedSecret;

/// Secp256k1 Public Key
pub struct PublicKey(k256::PublicKey);

// algorithm identifier used for errors
const NAME: &str = "Secp256k1";

impl PublicKey {
    /// Load a [PublicKey] from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        assert_buffer_eq!(bytes.len(), UntaggedPointSize::<Secp256k1>::USIZE, "bytes");

        EncodedPoint::from_untagged_bytes(bytes.into())
            .decode()
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "Secp256k1 Public Key",
            })
    }

    /// Load a [PublicKey] from big-endian serialized coordinates.
    pub fn from_coord(x: &[u8], y: &[u8]) -> crate::Result<Self> {
        let x: &FieldBytes = x.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "Secp256k1 Point (x)",
        })?;

        let y: &FieldBytes = y.try_into().map_err(|_| crate::Error::ConvertError {
            from: "bytes",
            to: "Secp256k1 Point (y)",
        })?;

        EncodedPoint::from_affine_coordinates(x, y, false)
            .try_into()
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "Coordinates",
                to: "Secp256k1 Public Key",
            })
    }

    /// Return the [PublicKey] as an array of bytes.
    pub fn to_bytes(&self) -> GenericArray<u8, UntaggedPointSize<Secp256k1>> {
        let point: EncodedPoint<Secp256k1> = self.0.to_encoded_point(false);

        // sanity check encoded point
        assert!(!point.is_compressed());
        assert!(!point.is_identity());

        // unwrap is okay - non-identity points are guaranteed by `PublicKey`.
        point.to_untagged_bytes().unwrap()
    }

    /// Serialize this public key as SEC1 encoded coordinates.
    pub fn to_coord(&self) -> crate::Result<(FieldBytes, FieldBytes)> {
        match self.0.to_encoded_point(false).coordinates() {
            Coordinates::Uncompressed { x, y } => Ok((*x, *y)),
            Coordinates::Identity | Coordinates::Compressed { .. } => Err(crate::Error::ConvertError {
                from: "Secp256k1 Public Key",
                to: "Coordinates",
            }),
        }
    }

    /// Verify that the given `message` and `signature` are authentic.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> crate::Result<()> {
        signature::Signature::from_bytes(signature)
            .and_then(|signature| Verifier::verify(self, message, &signature))
            .map_err(|_| crate::Error::SignatureError { alg: NAME })
    }
}

impl Verifier<Signature> for PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SigError> {
        k256::ecdsa::VerifyingKey::from(self.0.as_affine()).verify(message, &signature.0)
    }
}

/// Secp256k1 Secret Key
pub struct SecretKey(k256::SecretKey);

impl SecretKey {
    /// Generate a new random [SecretKey].
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bytes: FieldBytes = Default::default();

        crate::utils::rand::fill(&mut bytes[..])?;

        Self::from_bytes(&bytes[..])
    }

    /// Load a [SecretKey] from a slice of big-endian bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        k256::SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "Secp256k1 Secret Key",
            })
    }

    /// Return the [SecretKey] as a slice of bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_bytes()
    }

    /// Return the [PublicKey] which corresponds to this [SecretKey].
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Sign the given `message` and return a digital [signature][Signature].
    pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
        self.try_sign(message)
            .map_err(|_| crate::Error::SignatureError { alg: NAME })
    }

    /// Compute the Diffie-Hellman [SharedSecret] from the [SecretKey] and the given [PublicKey].
    pub fn diffie_hellman(&self, public: &PublicKey) -> SharedSecret {
        ecdh::diffie_hellman(self.0.secret_scalar(), public.0.as_affine())
    }
}

impl Signer<Signature> for SecretKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SigError> {
        k256::ecdsa::SigningKey::from(&self.0).try_sign(message).map(Signature)
    }
}

/// Secp256k1 Signature
#[derive(Debug)]
pub struct Signature(k256::ecdsa::Signature);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        k256::ecdsa::Signature::from_bytes(bytes).map(Self)
    }
}
