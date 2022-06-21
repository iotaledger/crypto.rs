// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::num::NonZeroUsize;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

pub mod consts {
    pub use generic_array::typenum::*;
}

/// A key used by an [`Aead`] implementation.
pub type Key<T> = GenericArray<u8, <T as Aead>::KeyLength>;

/// A nonce used by an [`Aead`] implementation.
pub type Nonce<T> = GenericArray<u8, <T as Aead>::NonceLength>;

/// A tag produced by an [`Aead`] implementation.
pub type Tag<T> = GenericArray<u8, <T as Aead>::TagLength>;

/// A common interface for AEAD encryption algorithms.
///
/// Example using [`Aes256Gcm`][`crate::ciphers::aes::Aes256Gcm`]:
///
/// ```rust
/// # #[cfg(all(feature = "random", feature = "aes-gcm"))]
/// # {
/// use crypto::ciphers::{
///     aes_gcm::Aes256Gcm,
///     traits::{Aead, Key, Nonce, Tag},
/// };
/// let plaintext: &[u8] = b"crypto.rs";
/// let associated_data: &[u8] = b"stronghodl";
/// let mut encrypted: Vec<u8> = vec![0; plaintext.len()];
/// let mut decrypted: Vec<u8> = vec![0; encrypted.len()];
/// let mut tag: Vec<u8> = vec![0; Aes256Gcm::TAG_LENGTH];
///
/// let key: Key<Aes256Gcm> = Default::default();
/// let nonce: Nonce<Aes256Gcm> = Aes256Gcm::random_nonce()?;
///
/// Aes256Gcm::try_encrypt(&key, &nonce, associated_data, plaintext, &mut encrypted, &mut tag)?;
///
/// Aes256Gcm::try_decrypt(&key, &nonce, associated_data, &mut decrypted, &encrypted, &tag)?;
///
/// assert_eq!(decrypted, plaintext);
///
/// # Ok::<(), crypto::Error>(())
/// # }
/// # #[cfg(not(feature = "random"))]
/// # Ok::<(), crypto::Error>(())
/// ```
pub trait Aead {
    /// The size of the [`key`][`Key`] required by this algorithm.
    type KeyLength: ArrayLength<u8>;

    /// The size of the [`nonce`][`Nonce`] required by this algorithm.
    type NonceLength: ArrayLength<u8>;

    /// The size of the [`tag`][`Tag`] produced by this algorithm.
    type TagLength: ArrayLength<u8>;

    /// A human-friendly identifier of this algorithm.
    const NAME: &'static str;

    /// A const version of [`Aead::KeyLength`].
    const KEY_LENGTH: usize = <Self::KeyLength as Unsigned>::USIZE;

    /// A const version of [`Aead::NonceLength`].
    const NONCE_LENGTH: usize = <Self::NonceLength as Unsigned>::USIZE;

    /// A const version of [`Aead::TagLength`].
    const TAG_LENGTH: usize = <Self::TagLength as Unsigned>::USIZE;

    /// Encrypt the given `plaintext` using `key`.
    ///
    /// The output is written to the `ciphertext`/`tag` buffers.
    fn encrypt(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut Tag<Self>,
    ) -> crate::Result<()>;

    /// Decrypt the given `ciphertext` using `key` and `tag`.
    ///
    /// The output is written to the `plaintext` buffer.
    fn decrypt(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &mut [u8],
        ciphertext: &[u8],
        tag: &Tag<Self>,
    ) -> crate::Result<usize>;

    /// Encrypt the given `plaintext` using `key`.
    ///
    /// The output is written to `ciphertext`.
    ///
    /// This is a version of [`Aead::encrypt`] with easier-to-use parameters.
    fn try_encrypt(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8],
    ) -> crate::Result<()> {
        let key: &Key<Self> = try_generic_array(key, "key")?;
        let nonce: &Nonce<Self> = try_generic_array(nonce, "nonce")?;

        let tag: &mut Tag<Self> = try_generic_array_mut(tag, "tag")?;

        Self::encrypt(key, nonce, associated_data, plaintext, ciphertext, tag)
    }

    /// Decrypt the given `ciphertext` using `key` and `tag`.
    ///
    /// The output is written to the `plaintext` buffer.
    ///
    /// This is a version of [`Aead::decrypt`] with easier-to-use parameters.
    fn try_decrypt(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &mut [u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> crate::Result<usize> {
        let key: &Key<Self> = try_generic_array(key, "key")?;
        let nonce: &Nonce<Self> = try_generic_array(nonce, "nonce")?;
        let tag: &Tag<Self> = try_generic_array(tag, "tag")?;

        Self::decrypt(key, nonce, associated_data, plaintext, ciphertext, tag)
    }

    /// Generates a random nonce with the correct size for this algorithm.
    #[cfg(feature = "random")]
    fn random_nonce() -> crate::Result<Nonce<Self>> {
        let mut nonce: Nonce<Self> = Default::default();

        crate::utils::rand::fill(&mut nonce)?;

        Ok(nonce)
    }

    /// Returns the size of the padding applied to the input buffer.
    ///
    /// Note: This is not applicable to all implementations.
    fn padsize(_: &[u8]) -> Option<NonZeroUsize> {
        None
    }
}

#[inline(always)]
fn try_generic_array<'a, T>(slice: &'a [u8], name: &'static str) -> crate::Result<&'a GenericArray<u8, T>>
where
    T: ArrayLength<u8>,
{
    if slice.len() == T::USIZE {
        Ok(slice.into())
    } else {
        Err(crate::Error::BufferSize {
            name,
            needs: T::USIZE,
            has: slice.len(),
        })
    }
}

#[inline(always)]
fn try_generic_array_mut<'a, T>(slice: &'a mut [u8], name: &'static str) -> crate::Result<&'a mut GenericArray<u8, T>>
where
    T: ArrayLength<u8>,
{
    if slice.len() == T::USIZE {
        Ok(slice.into())
    } else {
        Err(crate::Error::BufferSize {
            name,
            needs: T::USIZE,
            has: slice.len(),
        })
    }
}
