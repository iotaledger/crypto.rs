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

use crate::signers::Error;

use ed25519_dalek::{ExpandedSecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use signature::{Signature, Signer, Verifier};
use slip10::{derive_key_from_path, BIP32Path, Curve};
use zeroize::Zeroize;

use core::convert::AsRef;

/// Binary `Ed25519`-based `Seed` to derive private keys, public keys and signatures from.
#[derive(SecretDebug, SecretDisplay, SecretDrop)]
pub struct Ed25519Seed(ed25519_dalek::SecretKey);

impl Zeroize for Ed25519Seed {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Ed25519Seed {
    /// Creates a new random `Seed`.
    #[cfg(feature = "std")]
    pub fn rand() -> Self {
        // `ThreadRng` implements `CryptoRng` so it is safe to use in cryptographic contexts.
        // https://rust-random.github.io/rand/rand/trait.CryptoRng.html
        let mut rng = rand::thread_rng();
        Self(ed25519_dalek::SecretKey::generate(&mut rng))
    }

    /// View this seed as a byte array.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Convert this seed to a byte array.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Convert this seed to a byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            ed25519_dalek::SecretKey::from_bytes(bytes).map_err(|_| Error::ConvertError)?,
        ))
    }
}

/// Ed25519 private key.
#[derive(SecretDebug, SecretDisplay, SecretDrop)]
pub struct Ed25519PrivateKey(ed25519_dalek::SecretKey);

impl Zeroize for Ed25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

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

        Ok(Self(
            ed25519_dalek::SecretKey::from_bytes(&subseed).map_err(|_| Error::PrivateKeyError)?,
        ))
    }

    /// Returns the public counterpart of a private key.
    pub fn generate_public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey((&self.0).into())
    }

    /// View this private key as a byte array.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Convert this private key to a byte array.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Convert this private key to a byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            ed25519_dalek::SecretKey::from_bytes(bytes).map_err(|_| Error::ConvertError)?,
        ))
    }
}

impl Signer<Ed25519Signature> for Ed25519PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        let key: ExpandedSecretKey = (&self.0).into();
        Ok(Ed25519Signature(key.sign(msg, &(&self.0).into())))
    }
}

/// Ed25519 public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519PublicKey(ed25519_dalek::PublicKey);

impl Ed25519PublicKey {
    /// View this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Convert this public key to a byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            ed25519_dalek::PublicKey::from_bytes(bytes).map_err(|_| Error::ConvertError)?,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

impl Ed25519Signature {
    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

impl Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Self(ed25519_dalek::Signature::from_bytes(bytes)?))
    }
}
