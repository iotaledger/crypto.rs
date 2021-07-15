use crate::{Error, Result};

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 65;
pub const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 33;
pub const SIGNATURE_LENGTH: usize = 64;

/// Secret key (256-bit) on a secp256k1 curve.
pub struct SecretKey(libsecp256k1::SecretKey);

/// Public key on a secp256k1 curve.
pub struct PublicKey(libsecp256k1::PublicKey);

/// An ECDSA signature.
pub struct Signature(libsecp256k1::Signature);

/// Tag used for public key recovery from signatures.
pub struct RecoveryId(libsecp256k1::RecoveryId);

impl SecretKey {
    /// Get a secret key from a raw byte array.
    pub fn from_raw(bytes: &[u8; SECRET_KEY_LENGTH]) -> Result<Self> {
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
