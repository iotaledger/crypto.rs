// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::cmp::Ordering;
use core::convert::TryFrom;
use core::hash::{Hash, Hasher};

use zeroize::{ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "keccak")]
use crate::hashes::keccak::keccak256;

pub const PREHASH_LENGTH: usize = 32;

/// Secp256k1 ECDSA secret signing key, supports signing Keccak256 and SHA256 message hashes.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(k256::ecdsa::SigningKey);

impl SecretKey {
    pub const LENGTH: usize = 32;

    #[cfg(feature = "rand")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self(k256::ecdsa::SigningKey::random(&mut rng))
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
    pub fn generate_with<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        Self(k256::ecdsa::SigningKey::random(rng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(k256::ecdsa::VerifyingKey::from(&self.0))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; SecretKey::LENGTH]> {
        Zeroizing::new(self.0.to_bytes().into())
    }

    pub fn try_from_bytes(bytes: &[u8; SecretKey::LENGTH]) -> crate::Result<Self> {
        k256::ecdsa::SigningKey::from_bytes(bytes.into())
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "Secp256k1 ECDSA secret key",
            })
            .map(Self)
    }

    /// Generate Secp256k1 ECDSA signature of message hash.
    /// Signature generation can fail with a very low probability.
    pub fn try_sign_prehash(&self, prehash: &[u8; PREHASH_LENGTH]) -> crate::Result<RecoverableSignature> {
        self.0
            .sign_prehash_recoverable(prehash)
            .map_err(|_| crate::Error::SignatureError { alg: "Secp256k1 ECDSA" })
            .map(|(sig, rid)| RecoverableSignature(Signature(sig), rid))
    }

    /// Generate Secp256k1 ECDSA signature of Keccak256 hash value of a message as used in Ethereum.
    /// Signature generation can fail with a very low probability.
    #[cfg(feature = "keccak")]
    pub fn try_sign_keccak256(&self, msg: &[u8]) -> crate::Result<RecoverableSignature> {
        let mut prehash = [0_u8; PREHASH_LENGTH];
        keccak256(msg, &mut prehash);
        self.try_sign_prehash(&prehash)
    }

    /// Secp256k1 ECDSA signature of Keccak256 hash value of a message as used in Ethereum.
    #[cfg(feature = "keccak")]
    pub fn sign_keccak256(&self, msg: &[u8]) -> RecoverableSignature {
        self.try_sign_keccak256(msg).expect("Secp256k1 ECDSA sign failed")
    }

    /// Generate Standard Secp256k1 ECDSA signature of SHA256 hash value of a message.
    /// Signature generation can fail with a very low probability.
    pub fn try_sign_sha256(&self, msg: &[u8]) -> crate::Result<RecoverableSignature> {
        self.0
            .sign_recoverable(msg)
            .map_err(|_| crate::Error::SignatureError { alg: "Secp256k1 ECDSA" })
            .map(|(sig, rid)| RecoverableSignature(Signature(sig), rid))
    }

    /// Standard Secp256k1 ECDSA signature of SHA256 hash value of a message.
    pub fn sign_sha256(&self, msg: &[u8]) -> RecoverableSignature {
        self.try_sign_sha256(msg).expect("Secp256k1 ECDSA sign failed")
    }
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey(k256::ecdsa::VerifyingKey);

impl PublicKey {
    pub const LENGTH: usize = 33;

    /// Verify Secp256k1 ECDSA signature of a message hash.
    pub fn verify_prehash(&self, sig: &Signature, prehash: &[u8; PREHASH_LENGTH]) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        self.0.verify_prehash(prehash, &sig.0).is_ok()
    }

    /// Verify Secp256k1 ECDSA signature of Keccak256 hash of a message.
    #[cfg(feature = "keccak")]
    pub fn verify_keccak256(&self, sig: &Signature, msg: &[u8]) -> bool {
        let mut prehash = [0_u8; PREHASH_LENGTH];
        keccak256(msg, &mut prehash);
        self.verify_prehash(sig, &prehash)
    }

    /// Verify Secp256k1 ECDSA signature of SHA256 hash of a message.
    pub fn verify_sha256(&self, sig: &Signature, msg: &[u8]) -> bool {
        use k256::ecdsa::signature::Verifier;
        self.0.verify(msg, &sig.0).is_ok()
    }

    pub fn to_bytes(self) -> [u8; PublicKey::LENGTH] {
        let encoded_point = self.0.to_encoded_point(true);
        let slice = encoded_point.as_bytes();
        let mut bytes = [0_u8; PublicKey::LENGTH];
        bytes.copy_from_slice(slice);
        bytes
    }

    pub fn try_from_bytes(bytes: &[u8; PublicKey::LENGTH]) -> crate::Result<Self> {
        if bytes[0] == 2 || bytes[0] == 3 {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self)
                .map_err(|_| crate::Error::ConvertError {
                    from: "compressed bytes",
                    to: "Secp256k1 SEC1 compressed public key",
                })
        } else {
            Err(crate::Error::ConvertError {
                from: "compressed bytes",
                to: "Secp256k1 SEC1 compressed public key",
            })
        }
    }

    pub fn try_from_slice(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() == Self::LENGTH && (bytes[0] == 2 || bytes[0] == 3) {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self)
                .map_err(|_| crate::Error::ConvertError {
                    from: "compressed slice",
                    to: "Secp256k1 SEC1 compressed public key",
                })
        } else {
            Err(crate::Error::ConvertError {
                from: "compressed bytes",
                to: "Secp256k1 SEC1 compressed public key",
            })
        }
    }

    /// EVM Address is the last 20 bytes of Keccak256 hash of uncompressed public key coordinates.
    // credit: [secret_key_to_address](https://github.com/gakonst/ethers-rs/)
    #[cfg(feature = "keccak")]
    pub fn evm_address(&self) -> EvmAddress {
        // let public_key = secret_key.verifying_key();
        let public_key = self.0.to_encoded_point(/* compress = */ false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        let mut hash = [0_u8; 32];
        keccak256(&public_key[1..], &mut hash);

        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[12..]);
        EvmAddress::from(bytes)
    }
}

impl TryFrom<[u8; PublicKey::LENGTH]> for PublicKey {
    type Error = crate::Error;
    fn try_from(bytes: [u8; PublicKey::LENGTH]) -> crate::Result<Self> {
        Self::try_from_bytes(&bytes)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let encoded_point = self.0.to_encoded_point(true);
        encoded_point.as_bytes().hash(state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature(k256::ecdsa::Signature);

impl Signature {
    pub const LENGTH: usize = 64;

    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes().into()
    }

    pub fn try_from_bytes(sig: &[u8; Self::LENGTH]) -> crate::Result<Self> {
        Self::try_from_slice(sig)
    }

    pub fn try_from_slice(sig: &[u8]) -> crate::Result<Self> {
        k256::ecdsa::Signature::from_slice(sig)
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "Secp256k1 ECDSA signature",
            })
            .map(Self)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        let (r1, s1) = self.0.split_bytes();
        let (r2, s2) = other.0.split_bytes();
        r1.cmp(&r2).then(s1.cmp(&s2))
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecoverableSignature(
    Signature,
    #[cfg_attr(feature = "serde", serde(with = "serde_recovery_id"))] k256::ecdsa::RecoveryId,
);

impl AsRef<Signature> for RecoverableSignature {
    fn as_ref(&self) -> &Signature {
        &self.0
    }
}

impl RecoverableSignature {
    pub const LENGTH: usize = 65;

    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        let mut bytes = [0_u8; Self::LENGTH];
        bytes[0..64].copy_from_slice(&self.0.to_bytes());
        bytes[64] = self.1.into();
        bytes
    }

    const FROM_BYTES_CONVERT_ERROR: crate::Error = crate::Error::ConvertError {
        from: "bytes",
        to: "Secp256k1 ECDSA signature",
    };

    pub fn try_from_bytes(sig: &[u8; Self::LENGTH]) -> crate::Result<Self> {
        let rid = k256::ecdsa::RecoveryId::from_byte(sig[64]).ok_or(Self::FROM_BYTES_CONVERT_ERROR)?;
        k256::ecdsa::Signature::from_slice(&sig[..64])
            .map_err(|_| Self::FROM_BYTES_CONVERT_ERROR)
            .map(|s| Self(Signature(s), rid))
    }

    pub fn try_from_slice(sig: &[u8]) -> crate::Result<Self> {
        if sig.len() != Self::LENGTH {
            Err(Self::FROM_BYTES_CONVERT_ERROR)
        } else {
            let rid = k256::ecdsa::RecoveryId::from_byte(sig[64]).ok_or(Self::FROM_BYTES_CONVERT_ERROR)?;
            k256::ecdsa::Signature::from_slice(&sig[..64])
                .map_err(|_| Self::FROM_BYTES_CONVERT_ERROR)
                .map(|s| Self(Signature(s), rid))
        }
    }

    /// Recover public key from a Secp256k1 ECDSA signature of a message hash.
    pub fn recover_prehash(&self, prehash: &[u8; PREHASH_LENGTH]) -> Option<PublicKey> {
        k256::ecdsa::VerifyingKey::recover_from_prehash(prehash, &self.0 .0, self.1)
            .ok()
            .map(PublicKey)
    }

    /// Recover public key from a Secp256k1 ECDSA signature of Keccak256 hash of a message.
    #[cfg(feature = "keccak")]
    pub fn recover_keccak256(&self, msg: &[u8]) -> Option<PublicKey> {
        let mut prehash = [0_u8; PREHASH_LENGTH];
        keccak256(msg, &mut prehash);
        self.recover_prehash(&prehash)
    }

    /// Recover EVM Address from a Secp256k1 ECDSA signature of Keccak256 hash of a transaction.
    #[cfg(feature = "keccak")]
    pub fn recover_evm_address(&self, tx: &[u8]) -> Option<EvmAddress> {
        self.recover_keccak256(tx).map(|pk| pk.evm_address())
    }

    /// Recover public key from a Secp256k1 ECDSA signature of SHA256 hash of a message.
    pub fn recover_sha256(&self, msg: &[u8]) -> Option<PublicKey> {
        k256::ecdsa::VerifyingKey::recover_from_msg(msg, &self.0 .0, self.1)
            .ok()
            .map(PublicKey)
    }
}

#[cfg(feature = "serde")]
mod serde_recovery_id {
    pub fn serialize<S>(id: &k256::ecdsa::RecoveryId, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_u8(id.to_byte())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<k256::ecdsa::RecoveryId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use k256::ecdsa::RecoveryId;
        use serde::Deserialize;
        RecoveryId::from_byte(u8::deserialize(d)?)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid recovery byte (max {})", RecoveryId::MAX)))
    }
}

impl PartialOrd for RecoverableSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecoverableSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).then(self.1.cmp(&other.1))
    }
}

impl Hash for RecoverableSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
        self.1.to_byte().hash(state);
    }
}

mod evm_address {
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct EvmAddress([u8; Self::LENGTH]);

    impl EvmAddress {
        pub const LENGTH: usize = 20;
    }

    impl AsRef<[u8; EvmAddress::LENGTH]> for EvmAddress {
        fn as_ref(&self) -> &[u8; EvmAddress::LENGTH] {
            &self.0
        }
    }

    impl From<[u8; EvmAddress::LENGTH]> for EvmAddress {
        fn from(bytes: [u8; EvmAddress::LENGTH]) -> Self {
            Self(bytes)
        }
    }

    impl From<EvmAddress> for [u8; EvmAddress::LENGTH] {
        fn from(address: EvmAddress) -> Self {
            address.0
        }
    }
}

pub use evm_address::EvmAddress;
