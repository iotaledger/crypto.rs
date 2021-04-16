// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(deprecated)]

#[cfg(feature = "wots_deprecated_do_not_use")]
#[cfg_attr(docsrs, doc(cfg(feature = "wots_deprecated_do_not_use")))]
#[cfg_attr(not(test), deprecated)]
pub mod wots;

use crate::hashes::sponge::HASH_LENGTH;

use bee_ternary::{T1B1Buf, TritBuf, Trits, T1B1};

use zeroize::Zeroize;

/// Length of a message fragment.
pub const MESSAGE_FRAGMENT_LENGTH: usize = 27;

/// Length of a signature fragment.
pub const SIGNATURE_FRAGMENT_LENGTH: usize = MESSAGE_FRAGMENT_LENGTH * HASH_LENGTH;

/// A ternary private key.
pub trait PrivateKey: Zeroize {
    /// Matching public key type.
    type PublicKey: PublicKey;
    /// Generated signatures type.
    type Signature: Signature;
    /// Errors occuring while handling private keys.
    type Error;

    /// Returns the public counterpart of a private key.
    fn generate_public_key(&self) -> Result<Self::PublicKey, Self::Error>;

    /// Generates and returns a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * `message` A slice that holds a message to be signed.
    fn sign(&mut self, message: &Trits<T1B1>) -> Result<Self::Signature, Self::Error>;
}

/// A ternary public key.
pub trait PublicKey {
    /// Matching signature type.
    type Signature: Signature;
    /// Errors occuring while handling public keys.
    type Error;

    /// Verifies a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * `message`     A slice that holds a message to verify a signature for.
    /// * `signature`   The signature to verify.
    fn verify(&self, message: &Trits<T1B1>, signature: &Self::Signature) -> Result<bool, Self::Error>;

    /// Returns the size of the public key.
    fn size(&self) -> usize;

    /// Creates a public key from trits.
    fn from_trits(buf: TritBuf<T1B1Buf>) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Interprets the public key as trits.
    fn as_trits(&self) -> &Trits<T1B1>;
}

/// A ternary signature.
pub trait Signature {
    /// Errors occuring while handling public keys.
    type Error;

    /// Returns the size of the signature.
    fn size(&self) -> usize;

    /// Creates a signature from trits.
    fn from_trits(buf: TritBuf<T1B1Buf>) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Interprets the signature as trits.
    fn as_trits(&self) -> &Trits<T1B1>;
}

/// A ternary signature from which a public key can be recovered.
pub trait RecoverableSignature: Signature {
    /// Matching public key type.
    type PublicKey: PublicKey;
    /// Errors occuring while handling recoverable signatures.
    type Error;

    /// Recovers a public key from a signature.
    ///
    /// # Arguments
    ///
    /// * `message` A slice that holds a message to recover the public key from.
    fn recover_public_key(
        &self,
        message: &Trits<T1B1>,
    ) -> Result<Self::PublicKey, <Self as RecoverableSignature>::Error>;
}
