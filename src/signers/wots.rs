// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//! Binary seed to derive private keys, public keys and signatures from.
#[cfg(feature = "wots")]
use crate::signers::Error;

#[cfg(feature = "wots")]
use bee_common_derive::{SecretDebug, SecretDisplay, SecretDrop};
#[cfg(feature = "wots")]
use bee_crypto::ternary::{
    sponge::{Kerl, Sponge},
    HASH_LENGTH,
};
#[cfg(feature = "wots")]
use bee_ternary::{Btrit, T1B1Buf, Trit, TritBuf, Trits, Tryte, TryteBuf, T1B1};

#[cfg(feature = "wots")]
use rand::distributions::{Distribution, Uniform};
#[cfg(feature = "wots")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "wots")]
use signature::{Signature, Signer, Verifier};
#[cfg(feature = "wots")]
use zeroize::Zeroize;

#[cfg(feature = "wots")]
use std::convert::AsRef;

/// Length of a message fragment.
#[cfg(feature = "wots")]
pub const MESSAGE_FRAGMENT_LENGTH: usize = 27;

/// Length of a signature fragment.
#[cfg(feature = "wots")]
pub const SIGNATURE_FRAGMENT_LENGTH: usize = MESSAGE_FRAGMENT_LENGTH * HASH_LENGTH;

#[cfg(feature = "wots")]
/// Ternary `Kerl`-based `Seed` to derive private keys, public keys and signatures from.
#[derive(SecretDebug, SecretDisplay, SecretDrop)]
pub struct WotsSeed(TritBuf<T1B1Buf>);

#[cfg(feature = "wots")]
impl Zeroize for WotsSeed {
    fn zeroize(&mut self) {
        // This unsafe is fine since we only reset the whole buffer with zeros, there is no alignement issues.
        unsafe { self.0.as_i8_slice_mut().zeroize() }
    }
}

#[cfg(feature = "wots")]
impl WotsSeed {
    /// Creates a new random `Seed`.
    #[cfg(feature = "std")]
    pub fn rand() -> Self {
        // `ThreadRng` implements `CryptoRng` so it is safe to use in cryptographic contexts.
        // https://rust-random.github.io/rand/rand/trait.CryptoRng.html
        let mut rng = rand::thread_rng();
        let trits = [Btrit::NegOne, Btrit::Zero, Btrit::PlusOne];
        let range = Uniform::from(0..trits.len());
        let mut seed = [Btrit::Zero; HASH_LENGTH];

        for trit in seed.iter_mut() {
            *trit = trits[range.sample(&mut rng)];
        }

        Self(<&Trits>::from(&seed as &[_]).to_buf())
    }

    /// Creates a new `Seed` from the current `Seed` and an index.
    pub fn subseed(&self, index: usize) -> Self {
        let mut subseed = self.0.clone();

        for _ in 0..index {
            for t in subseed.iter_mut() {
                if let Some(ntrit) = t.checked_increment() {
                    *t = ntrit;
                    break;
                } else {
                    *t = Btrit::NegOne;
                }
            }
        }

        // Safe to unwrap since the size is known to be valid.
        Self(Kerl::default().digest(&subseed).unwrap())
    }

    /// Creates a `Seed` from trits.
    pub fn from_trits(buf: TritBuf<T1B1Buf>) -> Result<Self, Error> {
        if buf.len() != HASH_LENGTH {
            return Err(Error::InvalidLength(buf.len()));
        }

        Ok(Self(buf))
    }

    /// Returns the inner trits.
    pub fn as_trits(&self) -> &Trits<T1B1> {
        &self.0
    }
}

#[cfg(feature = "wots")]
/// Available WOTS security levels.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum WotsSecurityLevel {
    /// Low security.
    Low = 1,
    /// Medium security.
    Medium = 2,
    /// High security.
    High = 3,
}

#[cfg(feature = "wots")]
impl Default for WotsSecurityLevel {
    fn default() -> Self {
        WotsSecurityLevel::Medium
    }
}

#[cfg(feature = "wots")]
/// Winternitz One Time Signature private key.
#[derive(SecretDebug, SecretDisplay, SecretDrop)]
pub struct WotsPrivateKey(TritBuf<T1B1Buf>);

#[cfg(feature = "wots")]
impl Zeroize for WotsPrivateKey {
    fn zeroize(&mut self) {
        // This unsafe is fine since we only reset the whole buffer with zeros, there is no alignement issues.
        unsafe { self.0.as_i8_slice_mut().zeroize() }
    }
}

#[cfg(feature = "wots")]
impl WotsPrivateKey {
    /// Derives a private key from entropy using the provided ternary sponge construction.
    /// The entropy must be a slice of exactly 243 trits where the last trit is zero.
    //
    /// Deprecated: only generates secure keys for sponge constructions, but Kerl is not a true sponge construction.
    /// Consider using shake instead or sponge with Curl. In case that Kerl must be used in sponge, it must be assured
    /// that no chunk of the private key is ever revealed, as this would allow the reconstruction of successive chunks
    /// (also known as "M-bug").
    /// Provides compatibility to the currently used key derivation.
    pub fn generate_from_entropy(
        &self,
        seed: &WotsSeed,
        index: usize,
        security_level: WotsSecurityLevel,
    ) -> Result<Self, Error> {
        let subseed = seed.subseed(index);
        let entropy = subseed.as_trits();
        if entropy.len() != HASH_LENGTH {
            return Err(Error::InvalidLength(entropy.len()));
        }

        // This should only be checked if `Sponge` is `Kerl` but we are currently limited by the lack of specialization.
        if entropy[HASH_LENGTH - 1] != Btrit::Zero {
            return Err(Error::NonNullEntropyLastTrit);
        }

        let mut sponge = Kerl::default();
        let mut state = TritBuf::<T1B1Buf>::zeros(security_level as usize * SIGNATURE_FRAGMENT_LENGTH);

        sponge
            .digest_into(entropy, &mut state)
            .map_err(|_| Error::FailedSpongeOperation)?;

        Ok(WotsPrivateKey(state))
    }

    /// Returns the public counterpart of a private key.
    pub fn generate_public_key(&self) -> Result<WotsPublicKey, Error> {
        let mut sponge = Kerl::default();
        let mut hashed_private_key = self.0.clone();
        let security = self.0.len() / SIGNATURE_FRAGMENT_LENGTH;
        let mut digests = TritBuf::<T1B1Buf>::zeros(security * HASH_LENGTH);
        let mut public_key_state = TritBuf::<T1B1Buf>::zeros(HASH_LENGTH);

        // Hash each chunk of the private key the maximum amount of times.
        for chunk in hashed_private_key.chunks_mut(HASH_LENGTH) {
            for _ in 0..Tryte::MAX_VALUE as i8 - Tryte::MIN_VALUE as i8 {
                sponge
                    .absorb(chunk)
                    .and_then(|_| sponge.squeeze_into(chunk))
                    .map_err(|_| Error::FailedSpongeOperation)?;
                sponge.reset();
            }
        }

        // Create one digest per fragment of the private key.
        for (i, chunk) in hashed_private_key.chunks(SIGNATURE_FRAGMENT_LENGTH).enumerate() {
            sponge
                .digest_into(chunk, &mut digests[i * HASH_LENGTH..(i + 1) * HASH_LENGTH])
                .map_err(|_| Error::FailedSpongeOperation)?;
        }

        // Hash the digests together to produce the public key.
        sponge
            .digest_into(&digests, &mut public_key_state)
            .map_err(|_| Error::FailedSpongeOperation)?;

        Ok(WotsPublicKey(public_key_state))
    }

    /// Returns the inner trits.
    pub fn as_trits(&self) -> &Trits<T1B1> {
        &self.0
    }
}

// impl Signer<WotsSignature> for WotsPrivateKey {
//     fn try_sign(&self, msg: &[u8]) -> Result<WotsSignature, signature::Error> {
//         if message.len() != HASH_LENGTH {
//             return Err(Error::InvalidMessageLength(message.len()));
//         }

//         let mut sponge = S::default();
//         let mut signature = self.state.clone();

//         for (i, chunk) in signature.chunks_mut(HASH_LENGTH).enumerate() {
//             // Safe to unwrap because 3 trits can't underflow/overflow an i8.
//             let val = i8::try_from(&message[i * 3..i * 3 + 3]).unwrap();

//             // Hash each chunk of the private key an amount of times given by the corresponding byte of the message.
//             for _ in 0..(Tryte::MAX_VALUE as i8 - val) {
//                 sponge
//                     .absorb(chunk)
//                     .and_then(|_| sponge.squeeze_into(chunk))
//                     .map_err(|_| Self::Error::FailedSpongeOperation)?;
//                 sponge.reset();
//             }
//         }

//         Ok(Self::Signature {
//             state: signature,
//             sponge: PhantomData,
//         })
//     }
// }

#[cfg(feature = "wots")]
/// Ed25519 public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct WotsPublicKey(TritBuf<T1B1Buf>);

// TODO bytes conversion

// impl Verifier<Ed25519Signature> for WotsPublicKey {
//     fn verify(&self, msg: &[u8], signature: &Ed25519Signature) -> Result<(), signature::Error> {
//         self.0.verify(msg, &signature.0)?;
//         Ok(())
//     }
// }

#[cfg(feature = "wots")]
/// Winternitz One Time Signature signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WotsSignature(TritBuf<T1B1Buf>);

#[cfg(feature = "wots")]
impl WotsSignature {
    /// Creates a signature from trits.
    pub fn from_trits(state: TritBuf<T1B1Buf>) -> Result<Self, Error> {
        if state.len() % SIGNATURE_FRAGMENT_LENGTH != 0 {
            return Err(Error::InvalidSignatureLength(state.len()));
        }

        Ok(Self(state))
    }

    /// Interprets the signature as trits.
    pub fn as_trits(&self) -> &Trits<T1B1> {
        &self.0
    }
}

#[cfg(feature = "wots")]
impl AsRef<[u8]> for WotsSignature {
    fn as_ref(&self) -> &[u8] {
        // This is the alternative suggested by documentation in std::mem::transmute
        unsafe { &*(self.0.as_i8_slice() as *const _ as *const [u8]) }
    }
}

#[cfg(feature = "wots")]
impl Signature for WotsSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        // This is the alternative suggested by documentation in std::mem::transmute
        let slice = unsafe { &*(bytes as *const _ as *const [i8]) };
        let trit = TritBuf::<T1B1Buf>::from_i8s(slice).map_err(|_| signature::Error::new())?;
        Ok(WotsSignature(trit))
    }
}
