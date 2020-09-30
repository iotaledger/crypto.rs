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

extern crate rsa_ as rsa;

use core::fmt;
use rsa::PublicKey as _;
use rsa::PublicKeyParts as _;
use sha2::Digest as _;
use zeroize::Zeroize;

use crate::Error;
use crate::Result;

const RSA_ERR: Error = Error::SignatureError { alg: "rsa" };

// =============================================================================
// RSA Padding
// =============================================================================

mod padding {
    extern crate rsa_ as rsa;

    pub(crate) fn pkcs1_sha256() -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256))
    }

    pub(crate) fn pkcs1_sha384() -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_384))
    }

    pub(crate) fn pkcs1_sha512() -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_512))
    }

    pub(crate) fn pss_sha256<R>(rng: R) -> rsa::PaddingScheme
    where
        R: rand::RngCore + 'static,
    {
        rsa::PaddingScheme::new_pss::<sha2::Sha256, R>(rng)
    }

    pub(crate) fn pss_sha384<R>(rng: R) -> rsa::PaddingScheme
    where
        R: rand::RngCore + 'static,
    {
        rsa::PaddingScheme::new_pss::<sha2::Sha384, R>(rng)
    }

    pub(crate) fn pss_sha512<R>(rng: R) -> rsa::PaddingScheme
    where
        R: rand::RngCore + 'static,
    {
        rsa::PaddingScheme::new_pss::<sha2::Sha512, R>(rng)
    }
}

// =============================================================================
// RSA Bits
// =============================================================================

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum RsaBits {
    B2048,
    B3072,
    B4096,
}

impl RsaBits {
    pub const fn bits(self) -> usize {
        match self {
            Self::B2048 => 2048,
            Self::B3072 => 3072,
            Self::B4096 => 4096,
        }
    }
}

// =============================================================================
// RSA Public Key
// =============================================================================

#[derive(Clone, Debug)]
pub struct RsaPublicKey(rsa::RSAPublicKey);

impl RsaPublicKey {
    /// Creates a new `RsaPublicKey` from `n` (modulus) and `e` (exponent).
    pub fn new(n: rsa::BigUint, e: rsa::BigUint) -> Result<Self> {
        rsa::RSAPublicKey::new(n, e).map_err(|_| RSA_ERR).map(Self)
    }

    /// Creates an `RsaPublicKey` by parsing a PKCS#1-encoded document.
    pub fn from_pkcs1(pkcs1: impl AsRef<[u8]>) -> Result<Self> {
        rsa::RSAPublicKey::from_pkcs1(pkcs1.as_ref())
            .map_err(|_| RSA_ERR)
            .map(Self)
    }

    /// Creates an `RsaPublicKey` by parsing a PKCS#8-encoded document.
    pub fn from_pkcs8(pkcs8: impl AsRef<[u8]>) -> Result<Self> {
        rsa::RSAPublicKey::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| RSA_ERR)
            .map(Self)
    }

    /// Returns the modulus of the `RsaPublicKey`.
    pub fn n(&self) -> &rsa::BigUint {
        self.0.n()
    }

    /// Returns the public exponent of the `RsaPublicKey`.
    pub fn e(&self) -> &rsa::BigUint {
        self.0.e()
    }

    /// Verifies an RSA signature using RSASSA-PKCS#1.5 padding and SHA-256.
    pub fn verify_pkcs1_sha256(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(
            sha2::Sha256::digest(message.as_ref()),
            signature,
            padding::pkcs1_sha256(),
        )
    }

    /// Verifies an RSA signature using RSASSA-PKCS#1.5 padding and SHA-384.
    pub fn verify_pkcs1_sha384(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(
            sha2::Sha384::digest(message.as_ref()),
            signature,
            padding::pkcs1_sha384(),
        )
    }

    /// Verifies an RSA signature using RSASSA-PKCS#1.5 padding and SHA-512.
    pub fn verify_pkcs1_sha512(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(
            sha2::Sha512::digest(message.as_ref()),
            signature,
            padding::pkcs1_sha512(),
        )
    }

    /// Verifies an RSA signature using RSASSA-PSS padding and SHA-256.
    pub fn verify_pss_sha256<R>(
        &self,
        rng: R,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()>
    where
        R: rand::RngCore + 'static,
    {
        self.verify(
            sha2::Sha256::digest(message.as_ref()),
            signature,
            padding::pss_sha256(rng),
        )
    }

    /// Verifies an RSA signature using RSASSA-PSS padding and SHA-384.
    pub fn verify_pss_sha384<R>(
        &self,
        rng: R,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()>
    where
        R: rand::RngCore + 'static,
    {
        self.verify(
            sha2::Sha384::digest(message.as_ref()),
            signature,
            padding::pss_sha384(rng),
        )
    }

    /// Verifies an RSA signature using RSASSA-PSS padding and SHA-512.
    pub fn verify_pss_sha512<R>(
        &self,
        rng: R,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()>
    where
        R: rand::RngCore + 'static,
    {
        self.verify(
            sha2::Sha512::digest(message.as_ref()),
            signature,
            padding::pss_sha512(rng),
        )
    }

    /// Verifies an RSA signature using the specified padding algorithm.
    fn verify(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        padding: rsa::PaddingScheme,
    ) -> Result<()> {
        self.0
            .verify(padding, message.as_ref(), signature.as_ref())
            .map_err(|_| RSA_ERR)
    }
}

// =============================================================================
// RSA Private Key
// =============================================================================

#[derive(Clone)]
pub struct RsaPrivateKey(rsa::RSAPrivateKey);

impl RsaPrivateKey {
    /// Creates a new random `RsaPrivateKey`.
    pub fn random<R>(rng: &mut R, bits: RsaBits) -> Result<Self>
    where
        R: rand::Rng,
    {
        rsa::RSAPrivateKey::new(rng, bits.bits())
            .map_err(|_| RSA_ERR)
            .map(Self)
    }

    /// Creates an `RsaPrivateKey` by parsing a PKCS#1-encoded document.
    pub fn from_pkcs1(pkcs1: impl AsRef<[u8]>) -> Result<Self> {
        // Parse the private key from the input slice.
        let key: rsa::RSAPrivateKey =
            rsa::RSAPrivateKey::from_pkcs1(pkcs1.as_ref()).map_err(|_| RSA_ERR)?;

        // Ensure the key is well-formed.
        key.validate().map_err(|_| RSA_ERR)?;

        // Return the parse key.
        Ok(Self(key))
    }

    /// Creates an `RsaPrivateKey` by parsing a PKCS#8-encoded document.
    pub fn from_pkcs8(pkcs8: impl AsRef<[u8]>) -> Result<Self> {
        // Parse the private key from the input slice.
        let key: rsa::RSAPrivateKey =
            rsa::RSAPrivateKey::from_pkcs8(pkcs8.as_ref()).map_err(|_| RSA_ERR)?;

        // Ensure the key is well-formed.
        key.validate().map_err(|_| RSA_ERR)?;

        // Return the parse key.
        Ok(Self(key))
    }

    /// Creates an `RsaPublicKey` by cloning the public key components.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey(self.0.to_public_key())
    }

    /// Signs the given message using RSASSA-PKCS#1.5 padding and SHA-256.
    pub fn sign_pkcs1_sha256(&self, message: impl AsRef<[u8]>) -> Result<RsaSignature> {
        self.sign(
            sha2::Sha256::digest(message.as_ref()),
            padding::pkcs1_sha256(),
        )
    }

    /// Signs the given message using RSASSA-PKCS#1.5 padding and SHA-384.
    pub fn sign_pkcs1_sha384(&self, message: impl AsRef<[u8]>) -> Result<RsaSignature> {
        self.sign(
            sha2::Sha384::digest(message.as_ref()),
            padding::pkcs1_sha384(),
        )
    }

    /// Signs the given message using RSASSA-PKCS#1.5 padding and SHA-512.
    pub fn sign_pkcs1_sha512(&self, message: impl AsRef<[u8]>) -> Result<RsaSignature> {
        self.sign(
            sha2::Sha512::digest(message.as_ref()),
            padding::pkcs1_sha512(),
        )
    }

    /// Signs the given message using RSASSA-PSS padding and SHA-256.
    pub fn sign_pss_sha256<R>(&self, rng: R, message: impl AsRef<[u8]>) -> Result<RsaSignature>
    where
        R: rand::RngCore + 'static,
    {
        self.sign(
            sha2::Sha256::digest(message.as_ref()),
            padding::pss_sha256(rng),
        )
    }

    /// Signs the given message using RSASSA-PSS padding and SHA-384.
    pub fn sign_pss_sha384<R>(&self, rng: R, message: impl AsRef<[u8]>) -> Result<RsaSignature>
    where
        R: rand::RngCore + 'static,
    {
        self.sign(
            sha2::Sha384::digest(message.as_ref()),
            padding::pss_sha384(rng),
        )
    }

    /// Signs the given message using RSASSA-PSS padding and SHA-512.
    pub fn sign_pss_sha512<R>(&self, rng: R, message: impl AsRef<[u8]>) -> Result<RsaSignature>
    where
        R: rand::RngCore + 'static,
    {
        self.sign(
            sha2::Sha512::digest(message.as_ref()),
            padding::pss_sha512(rng),
        )
    }

    fn sign(&self, message: impl AsRef<[u8]>, padding: rsa::PaddingScheme) -> Result<RsaSignature> {
        self.0
            .sign(padding, message.as_ref())
            .map_err(|_| RSA_ERR)
            .map(Into::into)
            .map(RsaSignature)
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[Private]")
    }
}

impl Zeroize for RsaPrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// RSA Signature
// =============================================================================

#[derive(Clone, Debug)]
pub struct RsaSignature(Box<[u8]>);

impl AsRef<[u8]> for RsaSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// =============================================================================
// Tests
// =============================================================================

// https://github.com/RustCrypto/RSA/issues/60

#[cfg(test)]
mod tests {
    use crate::signers::rsa::RsaBits;
    use crate::signers::rsa::RsaPrivateKey;
    use crate::signers::rsa::RsaPublicKey;
    use crate::signers::rsa::RsaSignature;
    use rand::rngs::OsRng;

    #[test]
    fn test_rsa() {
        let secret: RsaPrivateKey = RsaPrivateKey::random(&mut OsRng, RsaBits::B2048).unwrap();
        let public: RsaPublicKey = secret.public_key();

        let signature: RsaSignature = secret.sign_pkcs1_sha256(b"pkcs1 sha256").unwrap();
        public
            .verify_pkcs1_sha256(b"pkcs1 sha256", signature)
            .unwrap();

        let signature: RsaSignature = secret.sign_pkcs1_sha384(b"pkcs1 sha384").unwrap();
        public
            .verify_pkcs1_sha384(b"pkcs1 sha384", signature)
            .unwrap();

        let signature: RsaSignature = secret.sign_pkcs1_sha512(b"pkcs1 sha512").unwrap();
        public
            .verify_pkcs1_sha512(b"pkcs1 sha512", signature)
            .unwrap();

        let signature: RsaSignature = secret.sign_pss_sha256(OsRng, b"pss sha256").unwrap();
        public
            .verify_pss_sha256(OsRng, b"pss sha256", signature)
            .unwrap();

        let signature: RsaSignature = secret.sign_pss_sha384(OsRng, b"pss sha384").unwrap();
        public
            .verify_pss_sha384(OsRng, b"pss sha384", signature)
            .unwrap();

        let signature: RsaSignature = secret.sign_pss_sha512(OsRng, b"pss sha512").unwrap();
        public
            .verify_pss_sha512(OsRng, b"pss sha512", signature)
            .unwrap();
    }
}
