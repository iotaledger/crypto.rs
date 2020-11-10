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

use core::convert::TryFrom;

pub const SECRET_KEY_LENGTH: usize = 32;
pub const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

pub struct SecretKey(ed25519_zebra::SigningKey);

impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey(ed25519_zebra::VerificationKey::from(&self.0))
    }

    pub fn to_le_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.into()
    }

    pub fn from_le_bytes(bs: [u8; SECRET_KEY_LENGTH]) -> crate::Result<Self> {
        Ok(SecretKey(ed25519_zebra::SigningKey::from(bs)))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

pub struct PublicKey(ed25519_zebra::VerificationKey);

impl PublicKey {
    pub fn to_compressed_bytes(&self) -> [u8; COMPRESSED_PUBLIC_KEY_LENGTH] {
        self.0.into()
    }

    pub fn from_compressed_bytes(bs: [u8; COMPRESSED_PUBLIC_KEY_LENGTH]) -> crate::Result<Self> {
        ed25519_zebra::VerificationKey::try_from(bs)
            .map(|vk| Self(vk))
            .map_err(|_| crate::Error::ConvertError {
                from: "compressed bytes", to: "Ed25519 public key"
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

pub fn verify(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
    match pk.0.verify(&sig.0, msg) {
        Ok(_) => true,
        Err(_) => false,
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

    #[test]
    fn test_vectors() {
        let tvs = [
            TestVector {
                secret_key: "c9ca40a493121e7510ffc0fda37cf0f97a7d3e08d3de53771d5a908b9b021bd0",
                public_key: "a5bd70055aeb203c8c53f81185d82fa3fd53372f4d8b65a47973d36224de2f6f",
                message: "e9a4924677e5f7679d2bdcf3c9b12b9cf2508486ed1d930bc33872791e76f673a234df09fb50e3985992162eac38865f60de813d386cdfbe9b84678cf56bfd9616dd53ecf9d454fe712e9abc26623c01491d1c8730855dec75ac3da77c47fce1261068737eea0c9409",
                signature: "de7b58c93f321912fa29aa3c3f07a559019b8dc1b6d0b1cb34640f99632ee02edddff29f25f6495c4dfac10666868b10ae4f0202c4efa2ded05efa9b9be2da0e",
            },
        ];

        for tv in tvs.iter() {
            let mut skb = [0; SECRET_KEY_LENGTH];
            hex::decode_to_slice(tv.secret_key, &mut skb as &mut [u8]).unwrap();
            let sk = SecretKey::from_le_bytes(skb).unwrap();
            assert_eq!(skb, sk.to_le_bytes());

            let mut pkb = [0; COMPRESSED_PUBLIC_KEY_LENGTH];
            hex::decode_to_slice(tv.public_key, &mut pkb as &mut [u8]).unwrap();
            assert_eq!(pkb, sk.public_key().to_compressed_bytes());
            let pk = PublicKey::from_compressed_bytes(pkb).unwrap();
            assert_eq!(pkb, pk.to_compressed_bytes());
            // TODO: assert_eq!(pk, sk.public_key()); why no equality on ed25519_zebra::VerificationKey?

            let msg = hex::decode(tv.message).unwrap();

            let mut sigb = [0; SIGNATURE_LENGTH];
            hex::decode_to_slice(tv.signature, &mut sigb as &mut [u8]).unwrap();
            assert_eq!(sigb, sk.sign(&msg).to_bytes());
            let sig = Signature::from_bytes(sigb);
            assert!(verify(&pk, &sig, &msg));
        }
    }
}

