// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

pub const SECRET_KEY_LENGTH: usize = 32;
pub const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

impl SecretKey {
    #[cfg(feature = "random")]
    pub fn generate() -> crate::Result<Self> {
        let mut bs = [0u8; SECRET_KEY_LENGTH];
        crate::rand::fill(&mut bs)?;
        Ok(Self(bs))
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    pub fn from_bytes(bs: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self(bs)
    }
}

impl AsRef<SecretKey> for SecretKey {
    fn as_ref(&self) -> &SecretKey {
        &self
    }
}

pub mod SHA512 {
    use super::*;
    use core::convert::TryFrom;

    // At the time of writing ed25519_zebra is implementing the Ed25519-SHA512 EdDSA scheme without
    // explicitly stating that fact:
    // https://github.com/ZcashFoundation/ed25519-zebra/blob/0e7a96a267a756e642e102a28a44dd79b9c7df69/src/signing_key.rs#L75

    pub struct IntermediateKey(ed25519_zebra::SigningKey);

    impl<T: AsRef<super::SecretKey>> From<T> for IntermediateKey {
        fn from(t: T) -> Self {
            Self(ed25519_zebra::SigningKey::from(t.as_ref().0))
        }
    }

    pub struct PublicKey(ed25519_zebra::VerificationKey);

    pub fn public_key<K: Into<IntermediateKey>>(k: K) -> PublicKey {
        PublicKey(ed25519_zebra::VerificationKey::from(&k.into().0))
    }

    impl PublicKey {
        pub fn to_compressed_bytes(&self) -> [u8; COMPRESSED_PUBLIC_KEY_LENGTH] {
            self.0.into()
        }

        pub fn from_compressed_bytes(bs: [u8; COMPRESSED_PUBLIC_KEY_LENGTH]) -> crate::Result<Self> {
            ed25519_zebra::VerificationKey::try_from(bs)
                .map(Self)
                .map_err(|_| crate::Error::ConvertError {
                    from: "compressed bytes",
                    to: "Ed25519 public key",
                })
        }
    }

    pub struct Signature(ed25519_zebra::Signature);

    impl Signature {
        pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
            self.0.into()
        }

        pub fn from_bytes(bs: [u8; SIGNATURE_LENGTH]) -> Self {
            Self(ed25519_zebra::Signature::from(bs))
        }
    }

    pub fn sign<K: Into<IntermediateKey>>(k: K, msg: &[u8]) -> Signature {
        Signature(k.into().0.sign(msg))
    }

    pub fn verify(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
        pk.0.verify(&sig.0, msg).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        secret_key: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    #[cfg(feature = "random")]
    pub fn fresh_key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    #[cfg(not(feature = "random"))]
    pub fn fresh_key() -> SecretKey {
        let mut bs = [0u8; SECRET_KEY_LENGTH];
        use rand::{rngs::OsRng, RngCore};
        OsRng.fill_bytes(&mut bs);
        SecretKey::from_bytes(bs)
    }

    #[test]
    fn test_vectors_SHA512() -> crate::Result<()> {
        let tvs = [
            // generated using: utils/test_vectors/py/main.py
            TestVector {
                secret_key: "f22d2d57c1a188e362f38c6789948df333e37ea3276357a1169cff12a2b7d100",
                public_key: "f24a3306ce8698c6bafb11f465f2be695f220fddbca69ca9cf133757c9c29378",
                message: "3a6e84dd6ccefaa125f9913020ce9680b41cbe9b685022b46011ce2f4a7a62d465a2e1a7519a169f9c2fa07ffcab91be1ac9aa2f9e4e1c3143cacc006b00fad92e9a66648620d665e3f834fa924519b7aaafe5cd84f81a98da343e15549dd2d6fcb1969916f3d6d1de55207452d704",
                signature: "e197a50432c58b2a6a7e9c5d3b00c25c1e1b415bb9f30613efaf9d4ab61ad9654ebb8a27555eaf984d6492480e5e0e70abe814ad3596536f0c9bfddc43a63802",
            },
            TestVector {
                secret_key: "7e828a3c369f1d963685aae2354ab7f3509bed9e6244a7d4c370daccb37ca606",
                public_key: "82eeba00688da228b83bbe32d6c2e2d548550ab3c6e30752d9fe2617e89f554d",
                message: "a4f664a6bd9f9ab149c69fba1fb0df33908dacef11571be476bf71dbd9e1262c2591f0fe86c6b0a35b2cd8f08d41c23f979678be69c92a50491433eb43",
                signature: "e4c5ff2662d13452356078e71e7587d589474c15316d2e1a036be9a4a5e8a9f58f451083a984bf936583da504be8deaf2ba27eca1f9fadc266fa1b0e4d05b002",
            },
            TestVector {
                secret_key: "571ec49b416372c19b71f9949546eaa489816f20cda32c59fcaaa7fe28317a30",
                public_key: "3b20f8c1f07e28a1f8346d01a65750d0e0c34f314c4079e7ede7df5a5751aca3",
                message: "3697b7d56247f4a086cee766ec0ed807e1097b853a1e5f81a9081a869aff9f4642d3e9147d82c778526226c3f342b06e1c4e37b13344f42354f73e2366855aa7726693c0cabd6fd9027ebffe7667a2c549a4357a9e8b7e387e9e4ebd504e3ec52358d35a133a2a4185e4de5d7a057c4d6964d44b1a0678a8d9c9c8932bd2a4af2609d01339be6aae02c7510ec0df22e8aa95a846c1bbe0f1f5ba2cad9322a310a94b811fce132b4ddc1628c7e135a159f15b5ad0c14171e94a2891c2bb31220d75084cba46890288733676aaf835",
                signature: "cbbcdefc4e8e38788c5c41069c1f381820a4b17c62a67f9fd792f9ea5b10b6bca24b65e92b2a15a2c831548c5d44ec70e59a6e11ec9a993a98414d00b00aea07",
            },
        ];

        for tv in tvs.iter() {
            let mut skb = [0; SECRET_KEY_LENGTH];
            hex::decode_to_slice(tv.secret_key, &mut skb as &mut [u8]).unwrap();
            let sk = SecretKey::from_bytes(skb);
            assert_eq!(skb, sk.to_bytes());

            let mut pkb = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
            hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
            assert_eq!(pkb, SHA512::public_key(&sk).to_compressed_bytes());
            let pk = SHA512::PublicKey::from_compressed_bytes(pkb)?;
            assert_eq!(pkb, pk.to_compressed_bytes());
            // TODO: assert_eq!(pk, sk.public_key()); why no equality on ed25519_zebra::VerificationKey?

            let msg = hex::decode(tv.message).unwrap();

            let mut sigb = [0; SIGNATURE_LENGTH];
            hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
            assert_eq!(sigb, SHA512::sign(&sk, &msg).to_bytes());
            let sig = SHA512::Signature::from_bytes(sigb);
            assert!(SHA512::verify(&pk, &sig, &msg));
            assert!(!SHA512::verify(&SHA512::public_key(fresh_key()), &sig, &msg));

            crate::test_utils::corrupt(&mut sigb);
            let incorrect_sig = SHA512::Signature::from_bytes(sigb);
            assert!(!SHA512::verify(&pk, &incorrect_sig, &msg));
        }

        Ok(())
    }

    #[test]
    fn test_generate() -> crate::Result<()> {
        let sk = fresh_key();
        let msg = crate::test_utils::fresh::bytestring();

        let sig = SHA512::sign(&sk, &msg);

        assert!(SHA512::verify(&SHA512::public_key(&sk), &sig, &msg));
        assert!(!SHA512::verify(&SHA512::public_key(fresh_key()), &sig, &msg));

        let mut sigb = sig.to_bytes();
        crate::test_utils::corrupt(&mut sigb);
        let incorrect_sig = SHA512::Signature::from_bytes(sigb);
        assert!(!SHA512::verify(&SHA512::public_key(sk), &incorrect_sig, &msg));

        Ok(())
    }
}
