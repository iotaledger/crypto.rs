// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Winternitz One Time Signature scheme.
//! https://eprint.iacr.org/2011/191.pdf.

extern crate alloc;

use crate::{
    hashes::ternary::{Sponge, HASH_LENGTH},
    keys::ternary::wots::WotsSecurityLevel,
    signatures::ternary::{
        PrivateKey, PublicKey, RecoverableSignature, Signature, MESSAGE_FRAGMENT_LENGTH_TRITS,
        MESSAGE_FRAGMENT_LENGTH_TRYTES, NUM_MESSAGE_FRAGMENTS, SIGNATURE_FRAGMENT_LENGTH,
    },
};

use bee_common_derive::{SecretDebug, SecretDisplay, SecretDrop};
use bee_ternary::{T1B1Buf, T3B1Buf, TritBuf, Trits, Tryte, T1B1, T3B1};

use zeroize::Zeroize;

use alloc::string::String;
use core::{
    convert::TryFrom,
    fmt::{self, Display, Formatter},
    marker::PhantomData,
};

/// Errors occuring during WOTS operations.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Missing security level in generator.
    MissingSecurityLevel,
    /// Failed sponge operation.
    FailedSpongeOperation,
    /// Invalid entropy length.
    InvalidEntropyLength(usize),
    /// Invalid message length.
    InvalidMessageLength(usize),
    /// Invalid public key length.
    InvalidPublicKeyLength(usize),
    /// Invalid signature length.
    InvalidSignatureLength(usize),
    /// Last trit of the entropy is not null.
    NonNullEntropyLastTrit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingSecurityLevel => write!(f, "Missing security level in generator."),
            Error::FailedSpongeOperation => write!(f, "Failed sponge operation."),
            Error::InvalidEntropyLength(length) => {
                write!(f, "Invalid entropy length, should be 243 trits, was {0}.", length)
            }
            Error::InvalidMessageLength(length) => {
                write!(f, "Invalid message length, should be 243 trits, was {0}.", length)
            }
            Error::InvalidPublicKeyLength(length) => {
                write!(f, "Invalid public key length, should be 243 trits, was {0}.", length)
            }
            Error::InvalidSignatureLength(length) => write!(
                f,
                "Invalid signature length, should be a multiple of 6561 trits, was {0}.",
                length
            ),
            Error::NonNullEntropyLastTrit => write!(f, "Last trit of the entropy is not null."),
        }
    }
}

/// Since the Winternitz One-Time Signature Scheme is based on hash chains, producing a signatures for a message - by
/// definition - also reveals all the signatures for messages that are element-wise larger than the original message.
/// As such, it is a crucial requirement for every W-OTS scheme to prevent this. While the original paper, mentioned
/// above, uses an additional checksum for exactly that purpose, this scheme normalizes the message (i.e. assures that
/// the sum over all it's elements is zero). Since no normalized messages can be element-wise larger than another
/// normalized messages, this attack vector is prevented.
pub fn normalize(message: &Trits<T1B1>) -> Result<TritBuf<T1B1Buf>, Error> {
    if message.len() != HASH_LENGTH {
        return Err(Error::InvalidMessageLength(message.len()));
    }

    let mut normalized = [0i8; WotsSecurityLevel::High as usize * MESSAGE_FRAGMENT_LENGTH_TRYTES];

    for i in 0..WotsSecurityLevel::High as usize {
        let mut sum: i16 = 0;

        for j in (i * MESSAGE_FRAGMENT_LENGTH_TRYTES)..((i + 1) * MESSAGE_FRAGMENT_LENGTH_TRYTES) {
            // Safe to unwrap because 3 trits can't underflow/overflow an i8.
            normalized[j] = i8::try_from(&message[j * 3..j * 3 + 3]).unwrap();
            sum += i16::from(normalized[j]);
        }

        while sum > 0 {
            for t in &mut normalized[i * MESSAGE_FRAGMENT_LENGTH_TRYTES..(i + 1) * MESSAGE_FRAGMENT_LENGTH_TRYTES] {
                if (*t as i8) > Tryte::MIN_VALUE as i8 {
                    *t -= 1;
                    break;
                }
            }
            sum -= 1;
        }

        while sum < 0 {
            for t in &mut normalized[i * MESSAGE_FRAGMENT_LENGTH_TRYTES..(i + 1) * MESSAGE_FRAGMENT_LENGTH_TRYTES] {
                if (*t as i8) < Tryte::MAX_VALUE as i8 {
                    *t += 1;
                    break;
                }
            }
            sum += 1;
        }
    }

    // This usage of unsafe is fine since we are creating the normalized trits inside this function and we know that the
    // content can't go wrong.
    Ok(unsafe {
        Trits::<T3B1>::from_raw_unchecked(&normalized, normalized.len() * 3)
            .to_buf::<T3B1Buf>()
            .encode::<T1B1Buf>()
    })
}

/// Winternitz One Time Signature private key.
#[derive(SecretDebug, SecretDisplay, SecretDrop)]
pub struct WotsPrivateKey<S> {
    pub(crate) state: TritBuf<T1B1Buf>,
    pub(crate) marker: PhantomData<S>,
}

impl<S> Zeroize for WotsPrivateKey<S> {
    fn zeroize(&mut self) {
        // This unsafe is fine since we only reset the whole buffer with zeros, there is no alignement issues.
        unsafe { self.state.as_i8_slice_mut().zeroize() }
    }
}

impl<S: Sponge + Default> PrivateKey for WotsPrivateKey<S> {
    type PublicKey = WotsPublicKey<S>;
    type Signature = WotsSignature<S>;
    type Error = Error;

    fn generate_public_key(&self) -> Result<Self::PublicKey, Self::Error> {
        let mut sponge = S::default();
        let mut hashed_private_key = self.state.clone();
        let security = self.state.len() / SIGNATURE_FRAGMENT_LENGTH;
        let mut digests = TritBuf::<T1B1Buf>::zeros(security * HASH_LENGTH);
        let mut public_key_state = TritBuf::<T1B1Buf>::zeros(HASH_LENGTH);

        // Hash each chunk of the private key the maximum amount of times.
        for chunk in hashed_private_key.chunks_mut(HASH_LENGTH) {
            for _ in 0..Tryte::MAX_VALUE as i8 - Tryte::MIN_VALUE as i8 {
                sponge
                    .absorb(chunk)
                    .and_then(|_| sponge.squeeze_into(chunk))
                    .map_err(|_| Self::Error::FailedSpongeOperation)?;
                sponge.reset();
            }
        }

        // Create one digest per fragment of the private key.
        for (i, chunk) in hashed_private_key.chunks(SIGNATURE_FRAGMENT_LENGTH).enumerate() {
            sponge
                .digest_into(chunk, &mut digests[i * HASH_LENGTH..(i + 1) * HASH_LENGTH])
                .map_err(|_| Self::Error::FailedSpongeOperation)?;
        }

        // Hash the digests together to produce the public key.
        sponge
            .digest_into(&digests, &mut public_key_state)
            .map_err(|_| Self::Error::FailedSpongeOperation)?;

        Ok(Self::PublicKey {
            state: public_key_state,
            marker: PhantomData,
        })
    }

    fn sign(&mut self, message: &Trits<T1B1>) -> Result<Self::Signature, Self::Error> {
        if message.len() != HASH_LENGTH {
            return Err(Error::InvalidMessageLength(message.len()));
        }

        let mut sponge = S::default();
        let mut signature = self.state.clone();

        for (f, fragment) in signature.chunks_mut(SIGNATURE_FRAGMENT_LENGTH).enumerate() {
            let message_fragment = &message[f % NUM_MESSAGE_FRAGMENTS * MESSAGE_FRAGMENT_LENGTH_TRITS
                ..(f % NUM_MESSAGE_FRAGMENTS + 1) * MESSAGE_FRAGMENT_LENGTH_TRITS];
            for (c, chunk) in fragment.chunks_mut(HASH_LENGTH).enumerate() {
                // Safe to unwrap because 3 trits can't underflow/overflow an i8.
                let val = i8::try_from(&message_fragment[c * 3..c * 3 + 3]).unwrap();

                // Hash each chunk of the private key an amount of times given by the corresponding byte of the message.
                for _ in 0..(Tryte::MAX_VALUE as i8 - val) {
                    sponge
                        .absorb(chunk)
                        .and_then(|_| sponge.squeeze_into(chunk))
                        .map_err(|_| Self::Error::FailedSpongeOperation)?;
                    sponge.reset();
                }
            }
        }

        Ok(Self::Signature {
            state: signature,
            marker: PhantomData,
        })
    }

    fn from_trits(state: TritBuf<T1B1Buf>) -> Result<Self, Self::Error> {
        if state.len() % SIGNATURE_FRAGMENT_LENGTH != 0 {
            return Err(Error::InvalidSignatureLength(state.len()));
        }

        Ok(Self {
            state,
            marker: PhantomData,
        })
    }

    fn as_trits(&self) -> &Trits<T1B1> {
        &self.state
    }
}

impl<S: Sponge + Default> WotsPrivateKey<S> {
    /// Returns the inner trits.
    pub fn as_trits(&self) -> &Trits<T1B1> {
        &self.state
    }
}

/// Winternitz One Time Signature public key.
pub struct WotsPublicKey<S> {
    state: TritBuf<T1B1Buf>,
    marker: PhantomData<S>,
}

impl<S: Sponge + Default> PublicKey for WotsPublicKey<S> {
    type Signature = WotsSignature<S>;
    type Error = Error;

    fn verify(&self, message: &Trits<T1B1>, signature: &Self::Signature) -> Result<bool, Self::Error> {
        Ok(signature.recover_public_key(message)?.state == self.state)
    }

    fn size(&self) -> usize {
        self.state.len()
    }

    fn from_trits(state: TritBuf<T1B1Buf>) -> Result<Self, Self::Error> {
        if state.len() != HASH_LENGTH {
            return Err(Error::InvalidPublicKeyLength(state.len()));
        }

        Ok(Self {
            state,
            marker: PhantomData,
        })
    }

    fn as_trits(&self) -> &Trits<T1B1> {
        &self.state
    }
}

impl<S: Sponge + Default> Display for WotsPublicKey<S> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.as_trits().iter_trytes().map(char::from).collect::<String>()
        )
    }
}

/// Winternitz One Time Signature signature.
pub struct WotsSignature<S> {
    state: TritBuf<T1B1Buf>,
    marker: PhantomData<S>,
}

impl<S: Sponge + Default> Signature for WotsSignature<S> {
    type Error = Error;

    fn size(&self) -> usize {
        self.state.len()
    }

    fn from_trits(state: TritBuf<T1B1Buf>) -> Result<Self, Self::Error> {
        if state.len() % SIGNATURE_FRAGMENT_LENGTH != 0 {
            return Err(Error::InvalidSignatureLength(state.len()));
        }

        Ok(Self {
            state,
            marker: PhantomData,
        })
    }

    fn as_trits(&self) -> &Trits<T1B1> {
        &self.state
    }
}

impl<S: Sponge + Default> RecoverableSignature for WotsSignature<S> {
    type PublicKey = WotsPublicKey<S>;
    type Error = Error;

    fn recover_public_key(
        &self,
        message: &Trits<T1B1>,
    ) -> Result<Self::PublicKey, <Self as RecoverableSignature>::Error> {
        if message.len() != HASH_LENGTH {
            return Err(Error::InvalidMessageLength(message.len()));
        }

        let mut sponge = S::default();
        let mut public_key_state = TritBuf::<T1B1Buf>::zeros(HASH_LENGTH);
        let security = self.state.len() / SIGNATURE_FRAGMENT_LENGTH;
        let mut digests = TritBuf::<T1B1Buf>::zeros(security * HASH_LENGTH);
        let mut hashed_signature = self.state.clone();

        for (f, fragment) in hashed_signature.chunks_mut(SIGNATURE_FRAGMENT_LENGTH).enumerate() {
            let message_fragment = &message[f % NUM_MESSAGE_FRAGMENTS * MESSAGE_FRAGMENT_LENGTH_TRITS
                ..(f % NUM_MESSAGE_FRAGMENTS + 1) * MESSAGE_FRAGMENT_LENGTH_TRITS];
            for (c, chunk) in fragment.chunks_mut(HASH_LENGTH).enumerate() {
                // Safe to unwrap because 3 trits can't underflow/overflow an i8.
                let val = i8::try_from(&message_fragment[c * 3..c * 3 + 3]).unwrap();

                // Hash each chunk of the signature an amount of times given by the corresponding byte of the message.
                for _ in 0..(val - Tryte::MIN_VALUE as i8) {
                    sponge
                        .absorb(chunk)
                        .and_then(|_| sponge.squeeze_into(chunk))
                        .map_err(|_| <Self as RecoverableSignature>::Error::FailedSpongeOperation)?;
                    sponge.reset();
                }
            }
        }

        // Create one digest per fragment of the signature.
        for (i, chunk) in hashed_signature.chunks(SIGNATURE_FRAGMENT_LENGTH).enumerate() {
            sponge
                .digest_into(chunk, &mut digests[i * HASH_LENGTH..(i + 1) * HASH_LENGTH])
                .map_err(|_| <Self as RecoverableSignature>::Error::FailedSpongeOperation)?;
        }

        // Hash the digests together to recover the public key.
        sponge
            .digest_into(&digests, &mut public_key_state)
            .map_err(|_| <Self as RecoverableSignature>::Error::FailedSpongeOperation)?;

        Ok(Self::PublicKey {
            state: public_key_state,
            marker: PhantomData,
        })
    }
}

impl<S: Sponge + Default> Display for WotsSignature<S> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.as_trits().iter_trytes().map(char::from).collect::<String>()
        )
    }
}
