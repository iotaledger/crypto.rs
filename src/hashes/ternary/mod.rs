// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Ternary sponge constructions.

#[cfg(feature = "curl-p")]
#[cfg_attr(docsrs, doc(cfg(feature = "curl-p")))]
pub mod curl_p;

#[cfg(feature = "kerl_deprecated_do_not_use")]
#[cfg_attr(docsrs, doc(cfg(feature = "kerl_deprecated_do_not_use")))]
#[cfg_attr(not(test), deprecated)]
pub mod kerl;

/// The length of a hash in units of balanced trits.
pub const HASH_LENGTH: usize = 243;
/// The length of a hash in trytes.
pub const HASH_LENGTH_TRYTES: usize = 243 / 3;

use core::ops::DerefMut;

use crate::encoding::ternary::{raw::RawEncoding, Btrit, TritBuf, Trits, T1B1};

/// The common interface of ternary cryptographic hash functions that follow the sponge construction.
pub trait Sponge {
    /// An error indicating that a failure has occured during a sponge operation.
    type Error;

    /// Reset the inner state of the sponge.
    fn reset(&mut self);

    /// Absorb `input` into the sponge.
    fn absorb(&mut self, input: &Trits) -> Result<(), Self::Error>;

    /// Squeeze the sponge into `buf`.
    fn squeeze_into(&mut self, buf: &mut Trits) -> Result<(), Self::Error>;

    /// Convenience function using `Sponge::squeeze_into` to return an owned output.
    fn squeeze(&mut self) -> Result<TritBuf, Self::Error> {
        let mut output = TritBuf::zeros(HASH_LENGTH);
        self.squeeze_into(&mut output)?;
        Ok(output)
    }

    /// Convenience function to absorb `input`, squeeze the sponge into `buf`, and reset the sponge.
    fn digest_into(&mut self, input: &Trits, buf: &mut Trits) -> Result<(), Self::Error> {
        self.absorb(input)?;
        self.squeeze_into(buf)?;
        self.reset();
        Ok(())
    }

    /// Convenience function to absorb `input`, squeeze the sponge, reset the sponge and return an owned output.
    fn digest(&mut self, input: &Trits) -> Result<TritBuf, Self::Error> {
        self.absorb(input)?;
        let output = self.squeeze()?;
        self.reset();
        Ok(output)
    }
}

impl<T: Sponge, U: DerefMut<Target = T>> Sponge for U {
    type Error = T::Error;

    fn reset(&mut self) {
        T::reset(self)
    }

    fn absorb(&mut self, input: &Trits) -> Result<(), Self::Error> {
        T::absorb(self, input)
    }

    fn squeeze_into(&mut self, buf: &mut Trits) -> Result<(), Self::Error> {
        T::squeeze_into(self, buf)
    }
}

#[derive(Debug)]
pub enum HashError {
    WrongLength,
}

/// Ternary cryptographic hash.
#[derive(Copy, Clone)]
pub struct Hash([Btrit; HASH_LENGTH]);

impl Hash {
    /// Creates a hash filled with zeros.
    pub fn zeros() -> Self {
        Self([Btrit::Zero; HASH_LENGTH])
    }

    /// Interpret the `Hash` as a trit slice.
    pub fn as_trits(&self) -> &Trits<T1B1> {
        self
    }

    /// Interpret the `Hash` as a mutable trit slice.
    pub fn as_trits_mut(&mut self) -> &mut Trits<T1B1> {
        &mut *self
    }

    /// Returns the weight - number of ending 0s - of the `Hash`.
    #[allow(clippy::cast_possible_truncation)] // `HASH_LENGTH` is smaller than `u8::MAX`.
    pub fn weight(&self) -> u8 {
        self.iter().rev().take_while(|t| *t == Btrit::Zero).count() as u8
    }
}

impl<'a, T: RawEncoding<Trit = Btrit>> core::convert::TryFrom<&'a Trits<T>> for Hash {
    type Error = HashError;

    fn try_from(trits: &'a Trits<T>) -> Result<Self, Self::Error> {
        if trits.len() == HASH_LENGTH {
            let mut hash = Self([Btrit::Zero; HASH_LENGTH]);
            hash.copy_from(trits);
            Ok(hash)
        } else {
            Err(HashError::WrongLength)
        }
    }
}

impl core::ops::Deref for Hash {
    type Target = Trits<T1B1>;

    fn deref(&self) -> &Trits<T1B1> {
        <&Trits>::from(&self.0 as &[_])
    }
}

impl DerefMut for Hash {
    fn deref_mut(&mut self) -> &mut Trits<T1B1> {
        <&mut Trits>::from(&mut self.0 as &mut [_])
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.as_trits() == other.as_trits()
    }
}

impl Eq for Hash {}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.as_trits())
    }
}

impl core::hash::Hash for Hash {
    fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
        self.0.hash(hasher)
    }
}
