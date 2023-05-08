// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::hash::{Hash, Hasher};

use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(ZeroizeOnDrop)]
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
                to: "secp256k1 ecdsa secret key",
            })
            .map(Self)
    }

    pub fn try_sign(&self, msg: &[u8]) -> crate::Result<Signature> {
        self.0
            .sign_recoverable(msg)
            .map_err(|_| crate::Error::SignatureError { alg: "secp256k1 ecdsa" })
            .map(|(sig, rid)| Signature(sig, rid))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.try_sign(msg).expect("secp256k1 ecdsa sign failed")
    }
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicKey(k256::ecdsa::VerifyingKey);

impl PublicKey {
    pub const LENGTH: usize = 33;

    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
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

    // credit: [secret_key_to_address](https://github.com/gakonst/ethers-rs/)
    pub fn to_evm_address(&self) -> EvmAddress {
        // let public_key = secret_key.verifying_key();
        let public_key = self.0.to_encoded_point(/* compress = */ false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        // let hash = keccak256(&public_key[1..]);
        use tiny_keccak::{Hasher, Keccak};
        let mut keccak = Keccak::v256();
        keccak.update(&public_key[1..]);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

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

pub struct Signature(k256::ecdsa::Signature, k256::ecdsa::RecoveryId);

impl Signature {
    pub const LENGTH: usize = 65;

    pub fn to_bytes(&self) -> [u8; Signature::LENGTH] {
        let mut bytes = [0_u8; Signature::LENGTH];
        bytes[0..64].copy_from_slice(&self.0.to_bytes());
        bytes[64] = self.1.into();
        bytes
    }

    pub fn try_from_bytes(sig: &[u8; Signature::LENGTH]) -> crate::Result<Self> {
        let rid = k256::ecdsa::RecoveryId::from_byte(sig[64]).ok_or(crate::Error::ConvertError {
            from: "bytes",
            to: "secp256k1 ecdsa signature",
        })?;
        k256::ecdsa::Signature::from_slice(&sig[..64])
            .map_err(|_| crate::Error::ConvertError {
                from: "bytes",
                to: "secp256k1 ecdsa signature",
            })
            .map(|s| Self(s, rid))
    }

    pub fn try_from_slice(sig: &[u8]) -> crate::Result<Self> {
        if sig.len() != Signature::LENGTH {
            Err(crate::Error::ConvertError {
                from: "slice",
                to: "secp256k1 ecdsa signature",
            })
        } else {
            let rid = k256::ecdsa::RecoveryId::from_byte(sig[64]).ok_or(crate::Error::ConvertError {
                from: "bytes",
                to: "secp256k1 ecdsa signature",
            })?;
            k256::ecdsa::Signature::from_slice(&sig[..64])
                .map_err(|_| crate::Error::ConvertError {
                    from: "slice",
                    to: "secp256k1 ecdsa signature",
                })
                .map(|s| Self(s, rid))
        }
    }

    pub fn verify_recover(&self, msg: &[u8]) -> Option<PublicKey> {
        k256::ecdsa::VerifyingKey::recover_from_msg(msg, &self.0, self.1)
            .ok()
            .map(PublicKey)
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
