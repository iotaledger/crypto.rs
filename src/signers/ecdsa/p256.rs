// Copyright 2020 IOTA Stiftung
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use core::convert::TryInto as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::Signature;
use p256::ecdsa::SigningKey;
use p256::ecdsa::VerifyKey;
use zeroize::Zeroize;

use crate::error::Error;
use crate::error::Result;
#[cfg(feature = "rand")]
use crate::rand::CryptoRng;
#[cfg(feature = "rand")]
use crate::rand::RngCore;

pub const P256_ERR: Error = Error::SignatureError {
    alg: "ecdsa (p-256)",
};

/// The size of an encoded point.
pub const FIELD_SIZE: usize = 32;

pub type Point = [u8; FIELD_SIZE];
pub type Coord = (Point, Point);

// =========================================================================
// ECDSA (P-256) Public Key
// =========================================================================

#[derive(Clone, Debug)]
pub struct PublicKey(VerifyKey);

impl PublicKey {
    /// Creates a `PublicKey` from big-endian bytes.
    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Result<Self> {
        VerifyKey::new(bytes.as_ref())
            .map_err(|_| P256_ERR)
            .map(Self)
    }

    /// Creates a `PublicKey` from an `SEC1` `EncodedPoint`.
    pub fn from_primitive(point: &p256::EncodedPoint) -> Result<Self> {
        VerifyKey::from_encoded_point(point)
            .map_err(|_| P256_ERR)
            .map(Self)
    }

    /// Verifies that the given message/signature combination is valid.
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<()> {
        let signature: Signature = signature.as_ref().try_into().map_err(|_| P256_ERR)?;

        self.0
            .verify(message.as_ref(), &signature)
            .map_err(|_| P256_ERR)?;

        Ok(())
    }
}

// =========================================================================
// ECDSA (P-256) Secret Key
// =========================================================================

pub struct PrivateKey(SigningKey);

impl PrivateKey {
    /// Creates a new random `PrivateKey`.
    #[cfg(feature = "rand")]
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self(SigningKey::random(rng))
    }

    /// Creates a `PrivateKey` from big-endian bytes.
    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Result<Self> {
        SigningKey::new(bytes.as_ref())
            .map_err(|_| P256_ERR)
            .map(Self)
    }

    /// Creates a `PublicKey` corresponding to this `PrivateKey`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verify_key())
    }

    /// Signs the given message with ECDSA using P-256 and SHA-256.
    pub fn sign(&self, message: impl AsRef<[u8]>) -> Result<Signature> {
        self.0.try_sign(message.as_ref()).map_err(|_| P256_ERR)
    }
}

impl_secret_debug!(PrivateKey);

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
