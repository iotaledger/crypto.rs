extern crate alloc;

pub use crate::keys::bip44::*;
use crate::{macs::hmac::HMAC_SHA512, Error, Result};

use alloc::vec::Vec;

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 65;
pub const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 33;
pub const SIGNATURE_LENGTH: usize = 64;

/// A seed is an arbitrary bytestring used to create the root of the tree.
///
/// The BIP32 standard restricts the size of the seed to be between 128 and 512 bits; 256 bits is advised.
pub struct Seed(Vec<u8>);

/// Secret key (256-bit) on a secp256k1 curve.
#[derive(Default)]
pub struct SecretKey(libsecp256k1::SecretKey);

/// Public key on a secp256k1 curve.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PublicKey(libsecp256k1::PublicKey);

/// An ECDSA signature.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Signature(libsecp256k1::Signature);

/// Tag used for public key recovery from signatures.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RecoveryId(libsecp256k1::RecoveryId);

/// ExtendedPrivateKey is used for child key derivation.
pub struct ExtendedPrivateKey {
    pub secret_key: SecretKey,
    pub chain_code: Vec<u8>,
}

impl ExtendedPrivateKey {
    pub fn child_key(&self, segment: &Segment) -> Result<Self> {
        let mut input = if segment.is_normal() {
            libsecp256k1::PublicKey::from_secret_key(&self.secret_key.0)
                .serialize_compressed()
                .to_vec()
        } else {
            let mut i = Vec::new();
            i.push(0);
            i.extend_from_slice(&self.secret_key.0.serialize());
            i
        };
        input.extend(segment.bs().to_vec());
        let mut result = [0; 64];
        HMAC_SHA512(&input, &self.chain_code, &mut result);
        let (secret_key, chain_code) = result.split_at(32);

        let mut secret_key = SecretKey::from_slice(&secret_key)?;
        secret_key.tweak_add(&self.secret_key)?;

        Ok(Self {
            secret_key,
            chain_code: chain_code.to_vec(),
        })
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn chain_code(&self) -> &[u8] {
        &self.chain_code
    }
}

impl Seed {
    pub fn from_bytes(bs: &[u8]) -> Self {
        Self(bs.to_vec())
    }

    pub fn derive(&self, chain: &Chain) -> Result<ExtendedPrivateKey> {
        let mut result = [0; 64];
        HMAC_SHA512(&self.0, b"Bitcoin seed", &mut result);
        let (secret_key, chain_code) = result.split_at(32);

        let mut sk = ExtendedPrivateKey {
            secret_key: SecretKey::from_slice(secret_key)?,
            chain_code: chain_code.to_vec(),
        };

        for segment in &chain.0 {
            sk = sk.child_key(segment)?;
        }

        Ok(sk)
    }
}

impl SecretKey {
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn generate() -> crate::Result<Self> {
        let mut bs = [0u8; SECRET_KEY_LENGTH];
        crate::utils::rand::fill(&mut bs)?;
        Self::from_bytes(&bs)
    }

    #[cfg(feature = "rand")]
    pub fn generate_with<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> crate::Result<Self> {
        let mut bs = [0_u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut bs);
        Self::from_bytes(&bs)
    }

    pub fn inner(&self) -> &libsecp256k1::SecretKey {
        &self.0
    }

    /// Get a secret key from a raw byte array.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Result<Self> {
        Ok(Self(libsecp256k1::SecretKey::parse(bytes).map_err(|_| {
            Error::InvalidArgumentError {
                alg: "bytes",
                expected: "a valid secret key byte array",
            }
        })?))
    }

    /// Get a secrey key from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self(libsecp256k1::SecretKey::parse_slice(bytes).map_err(|_| {
            Error::InvalidArgumentError {
                alg: "bytes",
                expected: "a valid secret key byte array",
            }
        })?))
    }

    /// Sign the specified hashed message.
    pub fn sign(&self, msg: &[u8; 32]) -> (Signature, RecoveryId) {
        let (signature, recovery_id) = libsecp256k1::sign(&libsecp256k1::Message::parse(msg), &self.0);
        (Signature(signature), RecoveryId(recovery_id))
    }

    /// Tweak a private key in place by adding tweak to it.
    pub fn tweak_add(&mut self, tweak: &SecretKey) -> Result<()> {
        self.0
            .tweak_add_assign(&tweak.0)
            .map_err(|_| Error::InvalidArgumentError {
                alg: "tweak_add",
                expected: "a valid tweak secret key",
            })
    }

    /// Tweak a private key in place by multiplying it by a tweak.
    pub fn tweak_mul(&mut self, tweak: &SecretKey) -> Result<()> {
        self.0
            .tweak_mul_assign(&tweak.0)
            .map_err(|_| Error::InvalidArgumentError {
                alg: "tweak_mul",
                expected: "a valid tweak secret key",
            })
    }

    /// Gets the byte array associated with this secret key.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.serialize()
    }

    /// Gets the public key associated with this secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(libsecp256k1::PublicKey::from_secret_key(&self.0))
    }
}

impl PublicKey {
    /// Get a public key from a full byte array.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self> {
        Ok(Self(libsecp256k1::PublicKey::parse(bytes).map_err(|_| {
            Error::InvalidArgumentError {
                alg: "bytes",
                expected: "a valid public key byte array",
            }
        })?))
    }

    /// Get a public key from a compressed byte array.
    pub fn from_compressed_bytes(bytes: &[u8; COMPRESSED_PUBLIC_KEY_LENGTH]) -> Result<Self> {
        Ok(Self(libsecp256k1::PublicKey::parse_compressed(bytes).map_err(
            |_| Error::InvalidArgumentError {
                alg: "bytes",
                expected: "a valid public key byte array",
            },
        )?))
    }

    /// Recover public key from a signed message.
    pub fn recover(message: &[u8; 32], signature: &Signature, recovery_id: &RecoveryId) -> Result<Self> {
        libsecp256k1::recover(&libsecp256k1::Message::parse(message), &signature.0, &recovery_id.0)
            .map(Self)
            .map_err(|_| Error::InvalidArgumentError {
                alg: "recover",
                expected: "a valid signature",
            })
    }

    /// Check signature is a valid message signed by this public key.
    pub fn verify(&self, message: &[u8; 32], signature: &Signature) -> bool {
        libsecp256k1::verify(&libsecp256k1::Message::parse(message), &signature.0, &self.0)
    }

    /// Gets the full byte array associated with public key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.serialize()
    }

    /// Gets the compressed byte array associated with this public key.
    pub fn to_compressed_bytes(&self) -> [u8; COMPRESSED_PUBLIC_KEY_LENGTH] {
        self.0.serialize_compressed()
    }
}

impl Signature {
    /// Gets a signature from a raw byte array.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Result<Self> {
        Ok(Self(libsecp256k1::Signature::parse_standard(bytes).map_err(|_| {
            Error::InvalidArgumentError {
                alg: "bytes",
                expected: "a valid signature byte array",
            }
        })?))
    }

    /// Gets the byte array associated with this signature.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.serialize()
    }
}

impl RecoveryId {
    /// Parse recovery ID starting with 0.
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(Self(libsecp256k1::RecoveryId::parse(b).map_err(|_| {
            Error::InvalidArgumentError {
                alg: "b",
                expected: "a valid recovery id",
            }
        })?))
    }
    /// Get the recovery id as a number.
    pub fn as_u8(&self) -> u8 {
        self.0.serialize()
    }
}
