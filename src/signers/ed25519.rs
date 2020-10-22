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

use crate::Error;

use ed25519_dalek::{ExpandedSecretKey/*, PUBLIC_KEY_LENGTH,*/ /*SECRET_KEY_LENGTH,*/ /*SIGNATURE_LENGTH*/};
use rand::{CryptoRng, RngCore};
use signature::{Signature, Signer, Verifier};
use slip10::{derive_key_from_path, BIP32Path, Curve};
use zeroize::Zeroize;

use ed25519_zebra;
pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;
use core::convert::TryFrom;

use core::convert::AsRef;

/// Binary `Ed25519`-based `Seed` to derive private keys, public keys and signatures from.
//#[derive(SecretDebug, SecretDisplay, SecretDrop)]
//pub struct Ed25519Seed(ed25519_dalek::SecretKey);
pub struct Ed25519Seed(ed25519_zebra::SigningKey);

/*impl Zeroize for Ed25519Seed {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}*/

impl Ed25519Seed {
    /// Creates a new random `Seed`.
    #[cfg(feature = "random")]
    pub fn rand<T>(rng: &mut T) -> Self
    where
        T: CryptoRng + RngCore
    {
        //Self(ed25519_dalek::SecretKey::generate(rng))
        Self(ed25519_zebra::SigningKey::new(rng))
    }

    /// View this seed as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Convert this seed to a byte array.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.into()
    }

    /// Convert this seed to a byte array.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Result<Self, Error> {
        let mut bytes_copied: [u8; SECRET_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];
        bytes_copied.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);
        Ok(Self(
            ed25519_zebra::SigningKey::try_from(bytes_copied).map_err(|_| Error::ConvertError)?,
        ))
    }
}

/// Ed25519 private key.
//#[derive(SecretDebug, SecretDisplay, SecretDrop)]
//pub struct Ed25519PrivateKey(ed25519_dalek::SecretKey);
pub struct Ed25519PrivateKey(ed25519_zebra::SigningKey);

//impl Zeroize for Ed25519PrivateKey {
    //fn zeroize(&mut self) {
        //self.0.zeroize()
    //}
//}

impl Ed25519PrivateKey {
    /// Deterministically generates and returns a private key from a seed and an index.
    ///
    /// # Arguments
    ///
    /// * `seed`    A seed to deterministically derive a private key from.
    pub fn generate_from_seed(seed: &Ed25519Seed, path: &BIP32Path) -> Result<Self, Error> {
        let subseed = derive_key_from_path(seed.as_bytes(), Curve::Ed25519, path)
            .map_err(|_| Error::PrivateKeyError)?
            .key;
        let mut subseed_bits: [u8; SECRET_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];
        subseed_bits.copy_from_slice(&subseed[..SECRET_KEY_LENGTH]);
        Ok(Self(
            ed25519_zebra::SigningKey::try_from(subseed_bits).map_err(|_| Error::PrivateKeyError)?,
        ))
    }

    /// Returns the public counterpart of a private key.
    pub fn generate_public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(ed25519_zebra::VerificationKey::from(&self.0))
    }

    /// View this private key as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Convert this private key to a byte array.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.into()
    }

    /// Convert this private key to a byte array.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Result<Self, Error> {
        let mut bytes_copied: [u8; SECRET_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];
        bytes_copied.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);
        Ok(Self(
            ed25519_zebra::SigningKey::try_from(bytes_copied).map_err(|_| Error::ConvertError)?,
        ))
    }
}

impl Signer<Ed25519Signature> for Ed25519PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        let key = (&self.0).into();
        Ok(Ed25519Signature(self.0.sign(msg, &(&self.0).into())))
    }
}

/// Ed25519 public key.
#[derive(Debug)]
pub struct Ed25519PublicKey(ed25519_zebra::VerificationKey);

impl Ed25519PublicKey {
    /// View this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.into()
    }

    /// Convert this public key to a byte array.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, Error> {
        let mut bytes_copied: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        bytes_copied.copy_from_slice(&bytes[..PUBLIC_KEY_LENGTH]);
        Ok(Self(
            ed25519_zebra::VerificationKey::try_from(bytes_copied).map_err(|_| Error::ConvertError)?,
        ))
    }
}

impl Verifier<Ed25519Signature> for Ed25519PublicKey {
    fn verify(&self, msg: &[u8], signature: &Ed25519Signature) -> Result<(), signature::Error> {
        self.0.verify(msg, &signature.0)?;
        Ok(())
    }
}

/// Ed25519 signature
#[derive(Clone, Debug)]
pub struct Ed25519Signature(ed25519_zebra::Signature);

impl Ed25519Signature {
    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.into()
    }
}

/*impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}*/

impl Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Self(ed25519_zebra::Signature::try_from(bytes)?))
    }
}
